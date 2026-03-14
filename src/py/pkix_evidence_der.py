"""
pkix_evidence_der.py
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
       subjectKeyIdentifier [1] EXPLICIT SubjectPublicKeyInfo OPTIONAL,
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
            "subjectKeyIdentifier",
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
# EvidenceKeyCapabilities  ::= SEQUENCE OF OBJECT IDENTIFIER
# ---------------------------------------------------------------------------

class EvidenceKeyCapabilities(univ.SequenceOf):
    componentType = univ.ObjectIdentifier()


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


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _fmt_oid(o: univ.ObjectIdentifier) -> str:
    """Return a human-readable name for an OID, falling back to dotted string."""
    dotted = ".".join(str(arc) for arc in o)
    return OID_NAMES.get(dotted, dotted)


def pretty_print_evidence(ev: Evidence, indent: int = 0) -> None:
    """Recursively print an Evidence structure to stdout."""
    pad = "  " * indent
    tbs = ev["tbs"]
    print(f"{pad}Evidence:")
    print(f"{pad}  TbsEvidence:")
    print(f"{pad}    version: {int(tbs['version'])}")

    for i, entity in enumerate(tbs["reportedEntities"]):
        print(f"{pad}    ReportedEntity[{i}]:")
        print(f"{pad}      entityType : {_fmt_oid(entity['entityType'])}")
        for j, claim in enumerate(entity["claims"]):
            ct = _fmt_oid(claim["claimType"])
            cv = claim["value"]
            if cv.hasValue():
                chosen = cv.getName()
                val    = cv.getComponent()
                print(f"{pad}      Claim[{j}]: {ct}")
                print(f"{pad}              -> [{chosen}] {val}")
            else:
                print(f"{pad}      Claim[{j}]: {ct}  (no value)")

    print(f"{pad}  Signatures ({len(ev['signatures'])}):")
    for i, sig in enumerate(ev["signatures"]):
        sid = sig["sid"]
        alg = _fmt_oid(sig["signatureAlgorithm"]["algorithm"])
        sv  = bytes(sig["signatureValue"]).hex()
        print(f"{pad}    SignatureBlock[{i}]:")
        print(f"{pad}      algorithm      : {alg}")
        print(f"{pad}      signatureValue : {sv[:48]}{'...' if len(sv) > 48 else ''}")
        if sid["keyId"].hasValue():
            print(f"{pad}      keyId          : {bytes(sid['keyId']).hex()}")
        if sid["subjectKeyIdentifier"].hasValue():
            spki_alg = _fmt_oid(
                sid["subjectKeyIdentifier"]["algorithm"]["algorithm"]
            )
            print(f"{pad}      SPKI algorithm : {spki_alg}")
        if sid["certificate"].hasValue():
            print(f"{pad}      certificate    : <present, rfc5280.Certificate>")


# ---------------------------------------------------------------------------
# Example builders
# ---------------------------------------------------------------------------

def build_example_evidence() -> Evidence:
    """
    Construct a realistic Evidence object covering all three entity types
    (transaction, platform, key) and one SignatureBlock.
    """

    # Transaction entity
    tx_claims = ReportedClaimSeq()
    tx_claims[0] = make_claim(
        "id-evidence-claim-transaction-nonce",
        b"\xde\xad\xbe\xef\xca\xfe\xba\xbe",
    )
    tx_claims[1] = ReportedClaim()
    tx_claims[1]["claimType"] = mkoid("id-evidence-claim-transaction-timestamp")
    tx_claims[1]["value"]     = make_claim_value_time("20250314120000Z")

    tx_entity = ReportedEntity()
    tx_entity["entityType"] = mkoid("id-evidence-entity-transaction")
    tx_entity["claims"]     = tx_claims

    # Platform entity
    plat_claims = ReportedClaimSeq()
    plat_claims[0] = make_claim("id-evidence-claim-platform-vendor",    "Acme Corp")
    plat_claims[1] = make_claim("id-evidence-claim-platform-hwmodel",   "HSM-9000")
    plat_claims[2] = make_claim("id-evidence-claim-platform-hwversion", "2.1.0")
    plat_claims[3] = make_claim("id-evidence-claim-platform-fipsboot",  True)
    plat_claims[4] = make_claim("id-evidence-claim-platform-fipslevel", 3)
    plat_claims[5] = make_claim("id-evidence-claim-platform-uptime",    86400)

    plat_entity = ReportedEntity()
    plat_entity["entityType"] = mkoid("id-evidence-entity-platform")
    plat_entity["claims"]     = plat_claims

    # Key entity
    key_claims = ReportedClaimSeq()
    key_claims[0] = make_claim(
        "id-evidence-claim-key-identifier",
        b"\x01\x02\x03\x04\x05\x06\x07\x08",
    )
    key_claims[1] = make_claim("id-evidence-claim-key-extractable",       False)
    key_claims[2] = make_claim("id-evidence-claim-key-never-extractable", True)
    key_claims[3] = make_claim("id-evidence-claim-key-sensitive",         True)
    key_claims[4] = make_claim("id-evidence-claim-key-local",             True)
    key_claims[5] = make_claim(
        "id-evidence-claim-key-purpose",
        tuple(int(x) for x in OID["id-evidence-key-capability-sign"].split(".")),
    )

    key_entity = ReportedEntity()
    key_entity["entityType"] = mkoid("id-evidence-entity-key")
    key_entity["claims"]     = key_claims

    # TbsEvidence
    tbs = TbsEvidence()
    tbs["version"] = 1
    entities = ReportedEntitySeq()
    entities[0] = tx_entity
    entities[1] = plat_entity
    entities[2] = key_entity
    tbs["reportedEntities"] = entities

    # SignatureBlock using rfc5280.AlgorithmIdentifier
    # ecdsa-with-SHA256  OID: 1.2.840.10045.4.3.2
    alg_id = AlgorithmIdentifier()
    alg_id["algorithm"] = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 2))
    # parameters absent for ECDSA per RFC 5480

    sid = SignerIdentifier()
    sid["keyId"] = b"\xAA\xBB\xCC\xDD\xEE\xFF"

    sig_block = SignatureBlock()
    sig_block["sid"]                = sid
    sig_block["signatureAlgorithm"] = alg_id
    sig_block["signatureValue"]     = univ.OctetString(b"\x00" * 64)  # placeholder

    sigs = SignatureBlockSeq()
    sigs[0] = sig_block

    # Evidence
    ev = Evidence()
    ev["tbs"]        = tbs
    ev["signatures"] = sigs
    # ev["intermediateCertificates"] intentionally absent (OPTIONAL)
    return ev


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


# ---------------------------------------------------------------------------
# Main — end-to-end DER round-trip demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    SEP = "=" * 62

    print(SEP)
    print("  PKIX-Evidence-2025  |  DER round-trip  (pyasn1_alt_modules)")
    print(SEP)

    # Evidence round-trip
    print("\n[1] Building Evidence ...")
    ev = build_example_evidence()

    print("[2] DER encoding ...")
    der = encode_evidence(ev)
    print(f"    {len(der)} bytes encoded")
    print(f"    Bytes: {der.hex()}")

    print("\n[3] DER decoding ...")
    ev2 = decode_evidence(der)

    print("\n[4] Decoded structure:")
    pretty_print_evidence(ev2, indent=1)

    print("\n[5] Re-encoding decoded object (round-trip check) ...")
    der2 = encode_evidence(ev2)
    assert der == der2, "ROUND-TRIP MISMATCH -- encoded bytes differ!"
    print("    OK  Bytes are identical -- round-trip passed")

    # EvidenceKeyCapabilities round-trip
    print(f"\n{SEP}")
    print("[6] Building EvidenceKeyCapabilities ...")
    caps = build_example_key_capabilities()
    der_caps = encode_key_capabilities(caps)
    print(f"    {len(der_caps)} bytes encoded")

    caps2 = decode_key_capabilities(der_caps)
    print("    Decoded capabilities:")
    for cap in caps2:
        print(f"      {_fmt_oid(cap)}")

    der_caps2 = encode_key_capabilities(caps2)
    assert der_caps == der_caps2, "ROUND-TRIP MISMATCH -- key capabilities differ!"
    print("    OK  Round-trip passed")

    # Confirm rfc5280 type provenance
    print(f"\n{SEP}")
    print("[7] Confirming rfc5280 type provenance ...")
    from pyasn1_alt_modules import rfc5280
    sig = ev2["signatures"][0]
    alg = sig["signatureAlgorithm"]
    assert type(alg) is rfc5280.AlgorithmIdentifier, (
        f"Expected rfc5280.AlgorithmIdentifier, got {type(alg)}"
    )
    print(f"    signatureAlgorithm type : {type(alg).__module__}.{type(alg).__qualname__}")
    print(f"    algorithm OID           : {_fmt_oid(alg['algorithm'])}")
    sid_decoded = ev2["signatures"][0]["sid"]
    print(f"    SignerIdentifier.keyId  : {bytes(sid_decoded['keyId']).hex()}")
    print("    OK  All rfc5280 types verified")
