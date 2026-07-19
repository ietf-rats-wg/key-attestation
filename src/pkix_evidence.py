"""
pkix_evidence.py
--------------------
pyasn1 + pyasn1_alt_modules DER encoder/decoder for PKIX-Evidence-2025.

Schema source : Pkix-Key-Attest-2025.asn
Encoding      : DER (Distinguished Encoding Rules)

Dependencies
------------
    pip install pyasn1 pyasn1_alt_modules

RFC 5280 types used directly from pyasn1_alt_modules.rfc5280:
  - AlgorithmIdentifier
  - SubjectPublicKeyInfo
  - Certificate
"""
import base64
from datetime import datetime, timezone
from evidence_oid_registry import oid_name, OID_NAMES, CLAIM_EXPECTED_TAGS, KNOWN_ELEMENT_OIDS, KNOWN_CLAIM_OIDS, evidence_make_oid

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from pyasn1.type import univ, namedtype, tag, constraint, char, useful
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple, tagFormatConstructed

# RFC 5280 canonical definitions — no stubs needed
from pyasn1_alt_modules.rfc5280 import (
    AlgorithmIdentifier,      # SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
    SubjectPublicKeyInfo,     # SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    Certificate,              # Full X.509 Certificate
)

from cryptography.hazmat.primitives import hashes, serialization

# ---------------------------------------------------------------------------
# id-kp OBJECT IDENTIFIER ::=
#  { iso(1) identified-organization(3) dod(6) internet(1)
#    security(5) mechanisms(5) pkix(7) kp(3) }
#
#  -- Attestation Key Extended Key Usage --
#
# id-kp-attestationKey OBJECT IDENTIFIER ::= { id-kp TBDMOD2 }
# ---------------------------------------------------------------------------
id_kp_attest_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.999")

# ---------------------------------------------------------------------------
# CLAIM ::= CLASS {
#     &id       OBJECT IDENTIFIER UNIQUE,
#     &Type
# } WITH SYNTAX {
#     ID &id
#     WITH TYPE &Type
# }
#
# ReportedClaim ::= SEQUENCE {
#     claimType  CLAIM.&id ({ClaimSet}),
#     value      CLAIM.&Type ({ClaimSet}{@claimType}) OPTIONAL
# }
# ---------------------------------------------------------------------------

class ReportedClaim(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("claimType", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("value", univ.Any()),
    )


class ReportedClaimSeq(univ.SequenceOf):
    componentType = ReportedClaim()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))


# ---------------------------------------------------------------------------
# ReportedElement ::= SEQUENCE {
#     elementType         OBJECT IDENTIFIER,
#     claims             SEQUENCE SIZE (1..MAX) OF ReportedClaim
# }
# ---------------------------------------------------------------------------

class ReportedElement(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("elementType", univ.ObjectIdentifier()),
        namedtype.NamedType("claims", ReportedClaimSeq()),
    )


class ReportedElementSeq(univ.SequenceOf):
    componentType = ReportedElement()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))


# ---------------------------------------------------------------------------
# TbsEvidence ::= SEQUENCE {
#     version INTEGER,
#     reportedElements SEQUENCE SIZE (1..MAX) OF ReportedElement
# }
# ---------------------------------------------------------------------------

class TbsEvidence(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("reportedElements", ReportedElementSeq()),
    )

# ---------------------------------------------------------------------------
# SignerIdentifier
#
# Uses rfc5280.SubjectPublicKeyInfo and rfc5280.Certificate directly.
# The three fields carry EXPLICIT tags (schema overrides the global
# IMPLICIT TAGS default with the EXPLICIT keyword per-field).
# ---------------------------------------------------------------------------

class SignerIdentifier(univ.Sequence):
    """
    SignerIdentifier ::= SEQUENCE {
       keyId                [0] EXPLICIT OCTET STRING         OPTIONAL,
       subjectPublicKeyInfo [1] EXPLICIT SubjectPublicKeyInfo OPTIONAL,
       certificate          [2] EXPLICIT Certificate          OPTIONAL
    }

    SubjectPublicKeyInfo and Certificate are imported from rfc5280.
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "keyId",
            univ.OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0))),
        namedtype.OptionalNamedType(
            "subjectPublicKeyInfo",
            SubjectPublicKeyInfo().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 1))),
        namedtype.OptionalNamedType(
            "certificate",
            Certificate().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 2))),
    )

# ---------------------------------------------------------------------------
# SignatureBlock
#
# signatureAlgorithm uses rfc5280.AlgorithmIdentifier directly.
# ---------------------------------------------------------------------------

class SignatureBlock(univ.Sequence):
    """
    SignatureBlock ::= SEQUENCE {
       sid                  SignerIdentifier,
       signatureAlgorithm   AlgorithmIdentifier,   -- rfc5280
       signatureValue       OCTET STRING
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("sid",                SignerIdentifier()),
        namedtype.NamedType("signatureAlgorithm", AlgorithmIdentifier()),
        namedtype.NamedType("signatureValue",     univ.OctetString()),
    )


class SignatureBlockSeq(univ.SequenceOf):
    componentType = SignatureBlock()
    subtypeSpec = constraint.ValueSizeConstraint(0, float("inf"))


# ---------------------------------------------------------------------------
# intermediateCertificates — SEQUENCE OF Certificate (rfc5280)
# ---------------------------------------------------------------------------

class CertificateSeq(univ.SequenceOf):
    """SEQUENCE OF Certificate  (rfc5280.Certificate)"""
    componentType = Certificate()


# ---------------------------------------------------------------------------
# EvidenceKeyCapabilities  ::= SEQUENCE OF OBJECT IDENTIFIER
# ---------------------------------------------------------------------------

class EvidenceKeyCapabilities(univ.SequenceOf):
    componentType = univ.ObjectIdentifier()


# ---------------------------------------------------------------------------
# Evidence  (top-level type)
# ---------------------------------------------------------------------------

class Evidence(univ.Sequence):
    """
    Evidence ::= SEQUENCE {
        tbs                           TbsEvidence,
        signatures                    SEQUENCE SIZE (0..MAX) OF SignatureBlock,
        intermediateCertificates  [0] SEQUENCE OF Certificate OPTIONAL
    }

    intermediateCertificates uses an IMPLICIT context tag [0] wrapping
    a SEQUENCE OF rfc5280.Certificate.
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tbs",        TbsEvidence()),
        namedtype.NamedType("signatures", SignatureBlockSeq()),
        namedtype.OptionalNamedType(
            "intermediateCertificates",
            CertificateSeq().subtype(
                implicitTag=Tag(tagClassContext, tagFormatConstructed, 0))),
    )



# ---------------------------------------------------------------------------
# PkixEvidence  (top-level external type)
# ---------------------------------------------------------------------------

class PkixEvidence:

    def __init__(self):
        # TbsEvidence
        self.tbs = TbsEvidence()
        self.tbs["version"] = 1
        self.tbs["reportedElements"] = ReportedElementSeq()

        self.sigs = SignatureBlockSeq()

    def add_element(self, element: ReportedElement):
        # if there were already any signatures, wipe them before changing the TbsEvidence
        self.sigs = SignatureBlockSeq()

        self.tbs['reportedElements'].append(element)

    def sign_and_encode(self, ak_cert: x509.Certificate, ak_private_key: ec.EllipticCurvePrivateKey, int_cert: x509.Certificate, includeCerts: bool = True):
        ''' Signs the evidence and returns the DER-encoded string'''

        # SignatureBlock using rfc5280.AlgorithmIdentifier
        # ecdsa-with-SHA256  OID: 1.2.840.10045.4.3.2
        alg_id = AlgorithmIdentifier()
        alg_id["algorithm"] = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 2))
        # parameters absent for ECDSA per RFC 5480

        sid = SignerIdentifier()
        if includeCerts:
            sid["certificate"] = tagged_component_value(
                sid["certificate"],
                convert_crypto_cert_to_pyasn1(ak_cert),
            )
        else:
            sid["keyId"] = ak_cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value.digest

        sig_block = SignatureBlock()
        sig_block["sid"] = sid
        sig_block["signatureAlgorithm"] = alg_id

        tbs_der = der_encoder.encode(self.tbs)
        signature = ak_private_key.sign(
            tbs_der,
            ec.ECDSA(hashes.SHA256()),
        )

        sig_block["signatureValue"] = univ.OctetString(signature)

        self.sigs.append(sig_block)

        if includeCerts:
            return self.encode([int_cert])
        else:
            return self.encode()


    def encode(self, int_certs: list[x509.Certificate] = []):
        # Evidence
        ev = Evidence()
        ev["tbs"] = self.tbs
        ev["signatures"] = self.sigs

        if len(int_certs) != 0:
            certs = CertificateSeq()
            for cert in int_certs:
                certs.append(convert_crypto_cert_to_pyasn1(cert))

            ev["intermediateCertificates"] = tagged_component_value(
                ev["intermediateCertificates"],
                certs,
            )

        return encode_evidence(ev)


# ---------------------------------------------------------------------------
# Helper: build a ClaimValue from a native Python value
# ---------------------------------------------------------------------------

def make_claim(claim_type_name: str, value=None) -> ReportedClaim:
    """
    Build a ReportedClaim.

    Parameters
    ----------
    claim_type_name : str
        A key from the OID dict (e.g. 'id-evidence-claim-platform-vendor')
        or a raw dotted OID string.
    value : optional
        Any value accepted by make_claim_value(), or None to omit the
        optional ClaimValue field entirely.
    """
    rc = ReportedClaim()
    rc["claimType"] = evidence_make_oid(claim_type_name)
    if value is not None:
        match claim_type_name:
            case "id-evidence-claim-transaction-nonce"\
                 | "id-evidence-claim-transaction-ak-spki"\
                 | "id-evidence-claim-platform-oemid"\
                 | "id-evidence-claim-platform-hwmodel"\
                 | "id-evidence-claim-platform-oemid"\
                 | "id-evidence-claim-platform-hwmodel"\
                 | "id-evidence-claim-key-spki":
                # OCTET STRING
                if isinstance(value, bytes):
                    rc["value"] = univ.OctetString(value)
                else:
                    raise Exception(f"Claim '{claim_type_name}' expects a value of type 'bytes'")
            case "id-evidence-claim-platform-vendor"\
                 | "id-evidence-claim-platform-hwversion"\
                 | "id-evidence-claim-platform-hwserial"\
                 | "id-evidence-claim-platform-swname"\
                 | "id-evidence-claim-platform-swversion"\
                 | "id-evidence-claim-platform-fipsver"\
                 | "id-evidence-claim-platform-fipsmodule"\
                 | "id-evidence-claim-key-identifier":
                # UTF8String
                if isinstance(value, str):
                    rc["value"] = char.UTF8String(value)
                else:
                    raise Exception(f"Claim '{claim_type_name}' expects a value of type 'str'")
            case "id-evidence-claim-platform-debugstat"\
                 | "id-evidence-claim-platform-uptime"\
                 | "id-evidence-claim-platform-bootcount"\
                 | "id-evidence-claim-platform-fipslevel":
                # INTEGER
                if isinstance(value, int):
                    rc["value"] = univ.Integer(value)
                else:
                    raise Exception(f"Claim '{claim_type_name}' expects a value of type 'int'")
            case "id-evidence-claim-platform-fipsboot"\
                 | "id-evidence-claim-key-extractable"\
                 | "id-evidence-claim-key-sensitive"\
                 | "id-evidence-claim-key-never-extractable"\
                 | "id-evidence-claim-key-local":
                # BOOLEAN
                if isinstance(value, bool):
                    rc["value"] = univ.Boolean(value)   
                else:
                    raise Exception(f"Claim '{claim_type_name}' expects a value of type 'bool'")
            case "id-evidence-claim-transaction-timestamp"\
                 | "id-evidence-claim-key-expiry":
                # GeneralizedTime
                if isinstance(value, useful.GeneralizedTime):
                    rc["value"] = value
                elif isinstance(value, str):
                    rc["value"] = useful.GeneralizedTime(value)
                else:
                    raise Exception(f"Claim '{claim_type_name}' expects a value of type 'str' or 'useful.GeneralizedTime'")
            case "id-evidence-claim-key-purpose":
                # List of OIDs
                if isinstance(value, (tuple, list)):
                    caps = EvidenceKeyCapabilities()
                    for i, name in enumerate(value):
                        caps[i] = evidence_make_oid(name)
                    rc["value"] = caps
                else:
                    raise Exception(f"Claim '{claim_type_name}' expects a value of type 'List[str]'")
            case _:
                raise Exception(f"Do not know of to make a claim based on type '{claim_type_name}'")
    return rc

    # EVIDENCE_KNOWN_OIDS.get("id-evidence-claim-key-purpose"):           16,  # SEQUENCE        (key-purpose / KeyPurposes)

# ---------------------------------------------------------------------------
# DER encode / decode — public API
# ---------------------------------------------------------------------------

def encode_evidence(ev: Evidence) -> bytes:
    """DER-encode an Evidence object and return the raw bytes."""
    return der_encoder.encode(ev)


def decode_evidence(der_bytes: bytes) -> Evidence:
    """
    DER-decode raw bytes into an Evidence object.

    Raises ValueError if there are unexpected trailing bytes.
    """
    obj, remainder = der_decoder.decode(der_bytes, asn1Spec=Evidence())
    if remainder:
        raise ValueError(
            f"Unexpected trailing bytes after DER decode: {bytes(remainder).hex()}"
        )
    return obj


def encode_key_capabilities(caps: EvidenceKeyCapabilities) -> bytes:
    """DER-encode an EvidenceKeyCapabilities object."""
    return der_encoder.encode(caps)


def decode_key_capabilities(der_bytes: bytes) -> EvidenceKeyCapabilities:
    """DER-decode raw bytes into an EvidenceKeyCapabilities object."""
    obj, remainder = der_decoder.decode(
        der_bytes, asn1Spec=EvidenceKeyCapabilities()
    )
    if remainder:
        raise ValueError(
            f"Unexpected trailing bytes after DER decode: {bytes(remainder).hex()}"
        )
    return obj


def encode_certificate(cert: Certificate) -> bytes:
    """DER-encode an rfc5280.Certificate."""
    return der_encoder.encode(cert)

def decode_certificate(der_bytes: bytes) -> Certificate:
    """DER-decode raw bytes into an rfc5280.Certificate."""
    obj, remainder = der_decoder.decode(der_bytes, asn1Spec=Certificate())
    if remainder:
        raise ValueError(
            f"Unexpected trailing bytes after DER decode: {bytes(remainder).hex()}"
        )
    return obj


def convert_crypto_cert_to_pyasn1(cert: x509.Certificate) -> Certificate:
    return decode_certificate(cert.public_bytes(encoding=serialization.Encoding.DER))


def tagged_component_value(schema_component, value):
    tagged = schema_component.clone()
    if isinstance(value, univ.SequenceOf):
        for idx, component in enumerate(value):
            tagged.setComponentByPosition(idx, component)
        return tagged

    for idx in range(len(value)):
        component = value.getComponentByPosition(idx)
        if component is not None and component.hasValue():
            tagged.setComponentByPosition(idx, component)
    return tagged

def build_key_capabilities_from_oids(oids:List[str]) -> EvidenceKeyCapabilities:
    """Build an EvidenceKeyCapabilities based on the provided OIDs. Each OID can be
    specified using a name (id-evidence-key-capability-sign) or a dotted notation (1.2.3.999.2.4)"""
    caps = EvidenceKeyCapabilities()
    for i, name in enumerate(oids):
        caps[i] = evidence_make_oid(name)
    return caps

