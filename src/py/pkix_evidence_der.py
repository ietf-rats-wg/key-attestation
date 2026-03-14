"""
pkix_evidence_der.py
--------------------
pyasn1-based DER encoder/decoder for PKIX-Evidence-2025.

Schema source: Pkix-Key-Attest-2025.asn
Encoding:      DER (Distinguished Encoding Rules)
Dependency:    pip install pyasn1
"""

from pyasn1.type import univ, namedtype, namedval, tag, constraint, char, useful
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple, tagFormatConstructed

# ---------------------------------------------------------------------------
# OID Registry
# ---------------------------------------------------------------------------

OID = {
    # Root
    "id-evidence":                              "1.2.3.999",

    # Entity types
    "id-evidence-entity":                       "1.2.3.999.0",
    "id-evidence-entity-transaction":           "1.2.3.999.0.0",
    "id-evidence-entity-platform":              "1.2.3.999.0.1",
    "id-evidence-entity-key":                   "1.2.3.999.0.2",

    # Claim root
    "id-evidence-claim":                        "1.2.3.999.1",

    # Transaction claims
    "id-evidence-claim-transaction":            "1.2.3.999.1.0",
    "id-evidence-claim-transaction-nonce":      "1.2.3.999.1.0.0",
    "id-evidence-claim-transaction-timestamp":  "1.2.3.999.1.0.1",
    "id-evidence-claim-transaction-ak-spki":    "1.2.3.999.1.0.2",

    # Platform claims
    "id-evidence-claim-platform":               "1.2.3.999.1.1",
    "id-evidence-claim-platform-vendor":        "1.2.3.999.1.1.0",
    "id-evidence-claim-platform-oemid":         "1.2.3.999.1.1.1",
    "id-evidence-claim-platform-hwmodel":       "1.2.3.999.1.1.2",
    "id-evidence-claim-platform-hwversion":     "1.2.3.999.1.1.3",
    "id-evidence-claim-platform-hwserial":      "1.2.3.999.1.1.4",
    "id-evidence-claim-platform-swname":        "1.2.3.999.1.1.5",
    "id-evidence-claim-platform-swversion":     "1.2.3.999.1.1.6",
    "id-evidence-claim-platform-debugstat":     "1.2.3.999.1.1.7",
    "id-evidence-claim-platform-uptime":        "1.2.3.999.1.1.8",
    "id-evidence-claim-platform-bootcount":     "1.2.3.999.1.1.9",
    "id-evidence-claim-platform-usermods":      "1.2.3.999.1.1.10",
    "id-evidence-claim-platform-fipsboot":      "1.2.3.999.1.1.11",
    "id-evidence-claim-platform-fipsver":       "1.2.3.999.1.1.12",
    "id-evidence-claim-platform-fipslevel":     "1.2.3.999.1.1.13",
    "id-evidence-claim-platform-fipsmodule":    "1.2.3.999.1.1.14",

    # Key claims
    "id-evidence-claim-key":                    "1.2.3.999.1.2",
    "id-evidence-claim-key-identifier":         "1.2.3.999.1.2.0",
    "id-evidence-claim-key-spki":               "1.2.3.999.1.2.1",
    "id-evidence-claim-key-extractable":        "1.2.3.999.1.2.2",
    "id-evidence-claim-key-sensitive":          "1.2.3.999.1.2.3",
    "id-evidence-claim-key-never-extractable":  "1.2.3.999.1.2.4",
    "id-evidence-claim-key-local":              "1.2.3.999.1.2.5",
    "id-evidence-claim-key-expiry":             "1.2.3.999.1.2.6",
    "id-evidence-claim-key-purpose":            "1.2.3.999.1.2.7",

    # Key capabilities
    "id-evidence-key-capability":               "1.2.3.999.2",
    "id-evidence-key-capability-encrypt":       "1.2.3.999.2.0",
    "id-evidence-key-capability-decrypt":       "1.2.3.999.2.1",
    "id-evidence-key-capability-wrap":          "1.2.3.999.2.2",
    "id-evidence-key-capability-unwrap":        "1.2.3.999.2.3",
    "id-evidence-key-capability-sign":          "1.2.3.999.2.4",
    "id-evidence-key-capability-sign-recover":  "1.2.3.999.2.5",
    "id-evidence-key-capability-verify":        "1.2.3.999.2.6",
    "id-evidence-key-capability-verify-recover":"1.2.3.999.2.7",
    "id-evidence-key-capability-derive":        "1.2.3.999.2.8",
}

# Reverse mapping: dotted-string OID -> name
OID_NAMES = {v: k for k, v in OID.items()}


def oid(name: str) -> univ.ObjectIdentifier:
    """Return a pyasn1 ObjectIdentifier for the given OID name or dotted string."""
    dotted = OID.get(name, name)
    return univ.ObjectIdentifier(
        [int(x) for x in dotted.split(".")]
    )


# ---------------------------------------------------------------------------
# Stub types for RFC 5280 structures
# (Full X.509 parsing is out of scope; treated as raw OCTET STRINGs here)
# ---------------------------------------------------------------------------

class AlgorithmIdentifier(univ.Sequence):
    """RFC 5280 AlgorithmIdentifier (simplified)."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("parameters", univ.Any()),
    )


class SubjectPublicKeyInfo(univ.Sequence):
    """RFC 5280 SubjectPublicKeyInfo (simplified)."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", AlgorithmIdentifier()),
        namedtype.NamedType("subjectPublicKey", univ.BitString()),
    )


# Certificate is complex; we model it as an opaque Any for now
Certificate = univ.Any


# ---------------------------------------------------------------------------
# ClaimValue  ::= CHOICE { ... }
# IMPLICIT TAGS context (schema uses IMPLICIT TAGS globally)
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
            univ.OctetString().subtype(implicitTag=Tag(
                tagClassContext, tagFormatSimple, 0)),
        ),
        namedtype.NamedType(
            "utf8String",
            char.UTF8String().subtype(implicitTag=Tag(
                tagClassContext, tagFormatSimple, 1)),
        ),
        namedtype.NamedType(
            "bool",
            univ.Boolean().subtype(implicitTag=Tag(
                tagClassContext, tagFormatSimple, 2)),
        ),
        namedtype.NamedType(
            "time",
            useful.GeneralizedTime().subtype(implicitTag=Tag(
                tagClassContext, tagFormatSimple, 3)),
        ),
        namedtype.NamedType(
            "int",
            univ.Integer().subtype(implicitTag=Tag(
                tagClassContext, tagFormatSimple, 4)),
        ),
        namedtype.NamedType(
            "oid",
            univ.ObjectIdentifier().subtype(implicitTag=Tag(
                tagClassContext, tagFormatSimple, 5)),
        ),
        namedtype.NamedType(
            "null",
            univ.Null().subtype(implicitTag=Tag(
                tagClassContext, tagFormatSimple, 6)),
        ),
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
# ---------------------------------------------------------------------------

class SignerIdentifier(univ.Sequence):
    """
    SignerIdentifier ::= SEQUENCE {
       keyId                [0] EXPLICIT OCTET STRING OPTIONAL,
       subjectKeyIdentifier [1] EXPLICIT SubjectPublicKeyInfo OPTIONAL,
       certificate          [2] EXPLICIT Certificate OPTIONAL
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "keyId",
            univ.OctetString().subtype(explicitTag=Tag(
                tagClassContext, tagFormatConstructed, 0)),
        ),
        namedtype.OptionalNamedType(
            "subjectKeyIdentifier",
            SubjectPublicKeyInfo().subtype(explicitTag=Tag(
                tagClassContext, tagFormatConstructed, 1)),
        ),
        namedtype.OptionalNamedType(
            "certificate",
            univ.Any().subtype(explicitTag=Tag(
                tagClassContext, tagFormatConstructed, 2)),
        ),
    )


# ---------------------------------------------------------------------------
# SignatureBlock
# ---------------------------------------------------------------------------

class SignatureBlock(univ.Sequence):
    """
    SignatureBlock ::= SEQUENCE {
       sid                SignerIdentifier,
       signatureAlgorithm AlgorithmIdentifier,
       signatureValue     OCTET STRING
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("sid", SignerIdentifier()),
        namedtype.NamedType("signatureAlgorithm", AlgorithmIdentifier()),
        namedtype.NamedType("signatureValue", univ.OctetString()),
    )


class SignatureBlockSeq(univ.SequenceOf):
    componentType = SignatureBlock()
    subtypeSpec = constraint.ValueSizeConstraint(0, float("inf"))


# ---------------------------------------------------------------------------
# Certificate sequence (for intermediateCertificates)
# ---------------------------------------------------------------------------

class CertificateSeq(univ.SequenceOf):
    componentType = univ.Any()


# ---------------------------------------------------------------------------
# Evidence  (top-level)
# ---------------------------------------------------------------------------

class Evidence(univ.Sequence):
    """
    Evidence ::= SEQUENCE {
        tbs                       TbsEvidence,
        signatures                SEQUENCE SIZE (0..MAX) OF SignatureBlock,
        intermediateCertificates  [0] SEQUENCE OF Certificate OPTIONAL
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tbs", TbsEvidence()),
        namedtype.NamedType("signatures", SignatureBlockSeq()),
        namedtype.OptionalNamedType(
            "intermediateCertificates",
            CertificateSeq().subtype(implicitTag=Tag(
                tagClassContext, tagFormatConstructed, 0)),
        ),
    )


# ---------------------------------------------------------------------------
# EvidenceKeyCapabilities
# ---------------------------------------------------------------------------

class EvidenceKeyCapabilities(univ.SequenceOf):
    """EvidenceKeyCapabilities ::= SEQUENCE OF OBJECT IDENTIFIER"""
    componentType = univ.ObjectIdentifier()


# ---------------------------------------------------------------------------
# Helper: build ClaimValue from a Python value
# ---------------------------------------------------------------------------

def make_claim_value(value) -> ClaimValue:
    """
    Automatically wrap a Python value in the appropriate ClaimValue CHOICE.

    Supported Python types:
      bytes        -> ClaimValue.bytes
      str          -> ClaimValue.utf8String
      bool         -> ClaimValue.bool     (check before int!)
      int          -> ClaimValue.int
      None         -> ClaimValue.null
      tuple/list   -> ClaimValue.oid  (e.g. (1,2,3,999))
      univ.ObjectIdentifier -> ClaimValue.oid
    """
    cv = ClaimValue()
    if value is None:
        cv["null"] = univ.Null()
    elif isinstance(value, bool):
        cv["bool"] = univ.Boolean(value)
    elif isinstance(value, bytes):
        cv["bytes"] = univ.OctetString(value)
    elif isinstance(value, str):
        cv["utf8String"] = char.UTF8String(value)
    elif isinstance(value, int):
        cv["int"] = univ.Integer(value)
    elif isinstance(value, (tuple, list)):
        cv["oid"] = univ.ObjectIdentifier(value)
    elif isinstance(value, univ.ObjectIdentifier):
        cv["oid"] = value
    else:
        raise TypeError(f"Unsupported ClaimValue type: {type(value)}")
    return cv


def make_claim(claim_type_name: str, value=None) -> ReportedClaim:
    """Build a ReportedClaim from an OID name and an optional Python value."""
    rc = ReportedClaim()
    rc["claimType"] = oid(claim_type_name)
    if value is not None:
        rc["value"] = make_claim_value(value)
    return rc


# ---------------------------------------------------------------------------
# DER encode / decode
# ---------------------------------------------------------------------------

def encode_evidence(evidence_obj: Evidence) -> bytes:
    """DER-encode an Evidence object to bytes."""
    return der_encoder.encode(evidence_obj)


def decode_evidence(der_bytes: bytes) -> Evidence:
    """DER-decode bytes into an Evidence object."""
    obj, remainder = der_decoder.decode(der_bytes, asn1Spec=Evidence())
    if remainder:
        raise ValueError(f"Trailing bytes after DER decode: {remainder.hex()}")
    return obj


def encode_key_capabilities(caps: EvidenceKeyCapabilities) -> bytes:
    """DER-encode an EvidenceKeyCapabilities object."""
    return der_encoder.encode(caps)


def decode_key_capabilities(der_bytes: bytes) -> EvidenceKeyCapabilities:
    """DER-decode bytes into an EvidenceKeyCapabilities object."""
    obj, remainder = der_decoder.decode(der_bytes, asn1Spec=EvidenceKeyCapabilities())
    if remainder:
        raise ValueError(f"Trailing bytes after DER decode: {remainder.hex()}")
    return obj


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _oid_str(o: univ.ObjectIdentifier) -> str:
    dotted = ".".join(str(x) for x in o)
    return OID_NAMES.get(dotted, dotted)


def pretty_print_evidence(ev: Evidence, indent: int = 0) -> None:
    pad = "  " * indent
    tbs = ev["tbs"]
    print(f"{pad}Evidence:")
    print(f"{pad}  version: {int(tbs['version'])}")
    for i, entity in enumerate(tbs["reportedEntities"]):
        print(f"{pad}  ReportedEntity[{i}]:")
        print(f"{pad}    entityType: {_oid_str(entity['entityType'])}")
        for j, claim in enumerate(entity["claims"]):
            ct = _oid_str(claim["claimType"])
            if claim["value"].hasValue():
                cv = claim["value"]
                chosen = cv.getName()
                val = cv.getComponent()
                print(f"{pad}    Claim[{j}]: {ct} = [{chosen}] {val}")
            else:
                print(f"{pad}    Claim[{j}]: {ct} (no value)")
    print(f"{pad}  Signatures: {len(ev['signatures'])}")
    for i, sig in enumerate(ev["signatures"]):
        sid = sig["sid"]
        alg = _oid_str(sig["signatureAlgorithm"]["algorithm"])
        sv  = bytes(sig["signatureValue"]).hex()
        print(f"{pad}    SignatureBlock[{i}]: alg={alg} value={sv[:32]}…")
        if sid["keyId"].hasValue():
            print(f"{pad}      keyId: {bytes(sid['keyId']).hex()}")


# ---------------------------------------------------------------------------
# End-to-end example
# ---------------------------------------------------------------------------

def build_example_evidence() -> Evidence:
    """Construct a realistic Evidence object from scratch."""

    # ---- Transaction entity ----
    tx_claims = ReportedClaimSeq()
    tx_claims[0] = make_claim(
        "id-evidence-claim-transaction-nonce",
        b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
    )
    tx_claims[1] = make_claim(
        "id-evidence-claim-transaction-timestamp",
        "20250314120000Z"          # GeneralizedTime string — stored as bytes here
    )

    tx_entity = ReportedEntity()
    tx_entity["entityType"] = oid("id-evidence-entity-transaction")
    tx_entity["claims"]     = tx_claims

    # ---- Platform entity ----
    plat_claims = ReportedClaimSeq()
    plat_claims[0] = make_claim("id-evidence-claim-platform-vendor",  "Acme Corp")
    plat_claims[1] = make_claim("id-evidence-claim-platform-hwmodel", "HSM-9000")
    plat_claims[2] = make_claim("id-evidence-claim-platform-fipsboot", True)
    plat_claims[3] = make_claim("id-evidence-claim-platform-uptime",   3600)

    plat_entity = ReportedEntity()
    plat_entity["entityType"] = oid("id-evidence-entity-platform")
    plat_entity["claims"]     = plat_claims

    # ---- Key entity ----
    key_claims = ReportedClaimSeq()
    key_claims[0] = make_claim(
        "id-evidence-claim-key-identifier",
        b"\x01\x02\x03\x04\x05\x06\x07\x08"
    )
    key_claims[1] = make_claim("id-evidence-claim-key-extractable",       False)
    key_claims[2] = make_claim("id-evidence-claim-key-never-extractable",  True)
    key_claims[3] = make_claim("id-evidence-claim-key-local",              True)
    key_claims[4] = make_claim(
        "id-evidence-claim-key-purpose",
        tuple(int(x) for x in OID["id-evidence-key-capability-sign"].split("."))
    )

    key_entity = ReportedEntity()
    key_entity["entityType"] = oid("id-evidence-entity-key")
    key_entity["claims"]     = key_claims

    # ---- TbsEvidence ----
    tbs = TbsEvidence()
    tbs["version"] = 1
    tbs["reportedEntities"] = ReportedEntitySeq()
    tbs["reportedEntities"][0] = tx_entity
    tbs["reportedEntities"][1] = plat_entity
    tbs["reportedEntities"][2] = key_entity

    # ---- SignatureBlock ----
    alg_id = AlgorithmIdentifier()
    alg_id["algorithm"] = univ.ObjectIdentifier(
        (1, 2, 840, 10045, 4, 3, 2)          # ecdsa-with-SHA256
    )

    sid = SignerIdentifier()
    sid["keyId"] = univ.OctetString(b"\xAA\xBB\xCC\xDD")

    sig_block = SignatureBlock()
    sig_block["sid"]              = sid
    sig_block["signatureAlgorithm"] = alg_id
    sig_block["signatureValue"]   = univ.OctetString(b"\x00" * 64)  # placeholder

    sigs = SignatureBlockSeq()
    sigs[0] = sig_block

    # ---- Evidence ----
    ev = Evidence()
    ev["tbs"]        = tbs
    ev["signatures"] = sigs
    return ev


def build_example_key_capabilities() -> EvidenceKeyCapabilities:
    caps = EvidenceKeyCapabilities()
    cap_names = [
        "id-evidence-key-capability-sign",
        "id-evidence-key-capability-verify",
        "id-evidence-key-capability-derive",
    ]
    for i, name in enumerate(cap_names):
        caps[i] = oid(name)
    return caps


# ---------------------------------------------------------------------------
# Main — run the round-trip demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  PKIX-Evidence-2025  |  DER round-trip demo")
    print("=" * 60)

    # ---- Evidence round-trip ----
    print("\n[1] Building Evidence object …")
    ev = build_example_evidence()

    print("[2] DER encoding …")
    der = encode_evidence(ev)
    print(f"    Encoded {len(der)} bytes")
    print(f"    Hex (first 64): {der[:64].hex()}")

    print("\n[3] DER decoding …")
    ev2 = decode_evidence(der)

    print("\n[4] Decoded structure:")
    pretty_print_evidence(ev2)

    print("\n[5] Re-encoding decoded object …")
    der2 = encode_evidence(ev2)
    assert der == der2, "Round-trip mismatch!"
    print("    Round-trip OK — encoded bytes are identical ✓")

    # ---- EvidenceKeyCapabilities round-trip ----
    print("\n" + "=" * 60)
    print("[6] Building EvidenceKeyCapabilities …")
    caps = build_example_key_capabilities()
    der_caps = encode_key_capabilities(caps)
    print(f"    Encoded {len(der_caps)} bytes")

    caps2 = decode_key_capabilities(der_caps)
    print("    Decoded capabilities:")
    for cap in caps2:
        print(f"      {_oid_str(cap)}")

    der_caps2 = encode_key_capabilities(caps2)
    assert der_caps == der_caps2, "Round-trip mismatch!"
    print("    Round-trip OK ✓")
