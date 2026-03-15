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

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from pathlib import Path

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

import create_ak
from cryptography.hazmat.primitives import hashes, serialization

# ---------------------------------------------------------------------------
# OID Registry
# ---------------------------------------------------------------------------

OID: dict = {
    # Root
    "id-evidence":                               "1.2.3.999",

    # Entity types
    "id-evidence-entity":                        "1.2.3.999.0",
    "id-evidence-entity-transaction":            "1.2.3.999.0.0",
    "id-evidence-entity-platform":               "1.2.3.999.0.1",
    "id-evidence-entity-key":                    "1.2.3.999.0.2",

    # Claim root
    "id-evidence-claim":                         "1.2.3.999.1",

    # Transaction claims
    "id-evidence-claim-transaction":             "1.2.3.999.1.0",
    "id-evidence-claim-transaction-nonce":       "1.2.3.999.1.0.0",
    "id-evidence-claim-transaction-timestamp":   "1.2.3.999.1.0.1",
    "id-evidence-claim-transaction-ak-spki":     "1.2.3.999.1.0.2",

    # Platform claims
    "id-evidence-claim-platform":                "1.2.3.999.1.1",
    "id-evidence-claim-platform-vendor":         "1.2.3.999.1.1.0",
    "id-evidence-claim-platform-oemid":          "1.2.3.999.1.1.1",
    "id-evidence-claim-platform-hwmodel":        "1.2.3.999.1.1.2",
    "id-evidence-claim-platform-hwversion":      "1.2.3.999.1.1.3",
    "id-evidence-claim-platform-hwserial":       "1.2.3.999.1.1.4",
    "id-evidence-claim-platform-swname":         "1.2.3.999.1.1.5",
    "id-evidence-claim-platform-swversion":      "1.2.3.999.1.1.6",
    "id-evidence-claim-platform-debugstat":      "1.2.3.999.1.1.7",
    "id-evidence-claim-platform-uptime":         "1.2.3.999.1.1.8",
    "id-evidence-claim-platform-bootcount":      "1.2.3.999.1.1.9",
    "id-evidence-claim-platform-usermods":       "1.2.3.999.1.1.10",
    "id-evidence-claim-platform-fipsboot":       "1.2.3.999.1.1.11",
    "id-evidence-claim-platform-fipsver":        "1.2.3.999.1.1.12",
    "id-evidence-claim-platform-fipslevel":      "1.2.3.999.1.1.13",
    "id-evidence-claim-platform-fipsmodule":     "1.2.3.999.1.1.14",

    # Key claims
    "id-evidence-claim-key":                     "1.2.3.999.1.2",
    "id-evidence-claim-key-identifier":          "1.2.3.999.1.2.0",
    "id-evidence-claim-key-spki":                "1.2.3.999.1.2.1",
    "id-evidence-claim-key-extractable":         "1.2.3.999.1.2.2",
    "id-evidence-claim-key-sensitive":           "1.2.3.999.1.2.3",
    "id-evidence-claim-key-never-extractable":   "1.2.3.999.1.2.4",
    "id-evidence-claim-key-local":               "1.2.3.999.1.2.5",
    "id-evidence-claim-key-expiry":              "1.2.3.999.1.2.6",
    "id-evidence-claim-key-purpose":             "1.2.3.999.1.2.7",

    # Key capabilities
    "id-evidence-key-capability":                "1.2.3.999.2",
    "id-evidence-key-capability-encrypt":        "1.2.3.999.2.0",
    "id-evidence-key-capability-decrypt":        "1.2.3.999.2.1",
    "id-evidence-key-capability-wrap":           "1.2.3.999.2.2",
    "id-evidence-key-capability-unwrap":         "1.2.3.999.2.3",
    "id-evidence-key-capability-sign":           "1.2.3.999.2.4",
    "id-evidence-key-capability-sign-recover":   "1.2.3.999.2.5",
    "id-evidence-key-capability-verify":         "1.2.3.999.2.6",
    "id-evidence-key-capability-verify-recover": "1.2.3.999.2.7",
    "id-evidence-key-capability-derive":         "1.2.3.999.2.8",
}

# Reverse mapping: dotted-string -> human name
OID_NAMES: dict = {v: k for k, v in OID.items()}
BASE_DIR = Path(__file__).resolve().parent
SAMPLEDATA_DIR = BASE_DIR.parent / "sampledata"


def mkoid(name: str) -> univ.ObjectIdentifier:
    """
    Return a pyasn1 ObjectIdentifier.

    Accepts either a registered name from the OID dict
    (e.g. "id-evidence-claim-key-sign") or a raw dotted
    string (e.g. "1.2.840.10045.4.3.2").
    """
    dotted = OID.get(name, name)
    return univ.ObjectIdentifier([int(x) for x in dotted.split(".")])


# ---------------------------------------------------------------------------
# ClaimValue  ::= CHOICE { ... }
#
# The schema declares IMPLICIT TAGS globally, so each context tag
# replaces (implicitly overrides) the inner type's universal tag.
# BOOLEAN and NULL keep primitive encoding; constructed types keep
# their natural format.
# ---------------------------------------------------------------------------

class ClaimValue(univ.Choice):
    """
    ClaimValue ::= CHOICE {
       bytes       [0] OCTET STRING,
       utf8String  [1] UTF8String,
       bool        [2] BOOLEAN,
       time        [3] GeneralizedTime,
       int         [4] INTEGER,
       oid         [5] OBJECT IDENTIFIER,
       null        [6] NULL
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "bytes",
            univ.OctetString().subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
        namedtype.NamedType(
            "utf8String",
            char.UTF8String().subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 1))),
        namedtype.NamedType(
            "bool",
            univ.Boolean().subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 2))),
        namedtype.NamedType(
            "time",
            useful.GeneralizedTime().subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 3))),
        namedtype.NamedType(
            "int",
            univ.Integer().subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 4))),
        namedtype.NamedType(
            "oid",
            univ.ObjectIdentifier().subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 5))),
        namedtype.NamedType(
            "null",
            univ.Null().subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 6))),
    )


# ---------------------------------------------------------------------------
# ReportedClaim  ::= SEQUENCE { claimType OID, value ClaimValue OPTIONAL }
# ---------------------------------------------------------------------------

class ReportedClaim(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("claimType", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("value", ClaimValue()),
    )


class ReportedClaimSeq(univ.SequenceOf):
    componentType = ReportedClaim()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))


# ---------------------------------------------------------------------------
# ReportedEntity  ::= SEQUENCE { entityType OID, claims SEQUENCE OF ... }
# ---------------------------------------------------------------------------

class ReportedEntity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("entityType", univ.ObjectIdentifier()),
        namedtype.NamedType("claims", ReportedClaimSeq()),
    )


class ReportedEntitySeq(univ.SequenceOf):
    componentType = ReportedEntity()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))


# ---------------------------------------------------------------------------
# TbsEvidence  ::= SEQUENCE { version INTEGER, reportedEntities ... }
# ---------------------------------------------------------------------------

class TbsEvidence(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("reportedEntities", ReportedEntitySeq()),
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

    entities = ReportedEntitySeq()

    def add_entity(self, entity: ReportedEntity):
        self.entities.append(entity)

    def sign_and_encode(self, ak_cert: x509.Certificate, ak_private_key: ec.EllipticCurvePrivateKey, int_cert: x509.Certificate):
        ''' Signs the evidence and returns the DER-encoded string'''

        # TbsEvidence
        tbs = TbsEvidence()
        tbs["version"] = 1
        # entities = ReportedEntitySeq()
        # entities[0] = tx_entity
        # entities[1] = plat_entity
        # entities[2] = key_entity
        tbs["reportedEntities"] = self.entities

        # SignatureBlock using rfc5280.AlgorithmIdentifier
        # ecdsa-with-SHA256  OID: 1.2.840.10045.4.3.2
        alg_id = AlgorithmIdentifier()
        alg_id["algorithm"] = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 2))
        # parameters absent for ECDSA per RFC 5480

        sid = SignerIdentifier()
        sid["keyId"] = ak_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
        sid["certificate"] = tagged_component_value(
            sid["certificate"],
            convert_crypto_cert_to_pyasn1(ak_cert),
        )

        sig_block = SignatureBlock()
        sig_block["sid"] = sid
        sig_block["signatureAlgorithm"] = alg_id

        tbs_der = der_encoder.encode(tbs)
        signature = ak_private_key.sign(
            tbs_der,
            ec.ECDSA(hashes.SHA256()),
        )

        sig_block["signatureValue"] = univ.OctetString(signature)

        sigs = SignatureBlockSeq()
        sigs[0] = sig_block

        # Evidence
        ev = Evidence()
        ev["tbs"] = tbs
        ev["signatures"] = sigs
        certs = CertificateSeq()
        certs[0] = convert_crypto_cert_to_pyasn1(int_cert)
        ev["intermediateCertificates"] = tagged_component_value(
            ev["intermediateCertificates"],
            certs,
        )

        return encode_evidence(ev)


# ---------------------------------------------------------------------------
# Helper: build a ClaimValue from a native Python value
# ---------------------------------------------------------------------------

def make_claim_value(value) -> ClaimValue:
    """
    Wrap a Python value in the correct ClaimValue CHOICE alternative.

    Python type  ->  ClaimValue alternative
    -----------     ----------------------
    bytes        ->  bytes       [0]
    str          ->  utf8String  [1]
    bool         ->  bool        [2]   (must be checked before int)
    int          ->  int         [4]
    None         ->  null        [6]
    tuple/list   ->  oid         [5]   e.g. (1, 2, 840, 10045, 4, 3, 2)
    univ.ObjectIdentifier -> oid [5]

    For GeneralizedTime use make_claim_value_time() instead.
    """
    cv = ClaimValue()
    if value is None:
        cv["null"] = univ.Null()
    elif isinstance(value, bool):           # bool subclasses int — check first
        cv["bool"] = value
    elif isinstance(value, bytes):
        cv["bytes"] = value
    elif isinstance(value, str):
        cv["utf8String"] = value
    elif isinstance(value, int):
        cv["int"] = value
    elif isinstance(value, useful.GeneralizedTime):
        cv["time"] = value
    elif isinstance(value, (tuple, list)):
        cv["oid"] = value
    elif isinstance(value, univ.ObjectIdentifier):
        cv["oid"] = value
    else:
        raise TypeError(f"Cannot map Python type {type(value)!r} to ClaimValue")
    return cv


def make_claim_value_time(generalized_time_str: str) -> ClaimValue:
    """
    Wrap a GeneralizedTime string (e.g. '20250314120000Z') in ClaimValue.time.
    """
    cv = ClaimValue()
    cv["time"] = generalized_time_str
    return cv


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
    rc["claimType"] = mkoid(claim_type_name)
    if value is not None:
        rc["value"] = make_claim_value(value)
    return rc


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


def build_example_key_capabilities() -> EvidenceKeyCapabilities:
    """Build an EvidenceKeyCapabilities listing sign, verify, and derive."""
    caps = EvidenceKeyCapabilities()
    for i, name in enumerate([
        "id-evidence-key-capability-sign",
        "id-evidence-key-capability-verify",
        "id-evidence-key-capability-derive",
    ]):
        caps[i] = mkoid(name)
    return caps


