"""
pkix_evidence_2025.py
=====================
Parser and verifier for PKIX-Evidence-2025 (IETF RATS WG Key Attestation)
Based on: https://raw.githubusercontent.com/ietf-rats-wg/key-attestation/refs/heads/main/Pkix-Key-Attest-2025.asn
 
ASN.1 Structure Summary
------------------------
Evidence ::= SEQUENCE {
    tbs                     TbsEvidence,
    signatures              SEQUENCE OF SignatureBlock,
    intermediateCertificates [0] SEQUENCE OF Certificate OPTIONAL
}
 
TbsEvidence ::= SEQUENCE {
    version          INTEGER,
    reportedElements SEQUENCE OF ReportedElement
}
 
ReportedElement ::= SEQUENCE {
    elementType  OBJECT IDENTIFIER,
    claims      SEQUENCE OF ReportedClaim
}
 
ReportedClaim ::= SEQUENCE {
    claimType  OBJECT IDENTIFIER,
    value      ANY OPTIONAL
}
 
Dependencies: pyasn1, pyasn1-modules, cryptography
    pip install pyasn1 pyasn1-modules cryptography
"""
 
from __future__ import annotations
 
import sys
import hashlib
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from generalized_time_validator import validate_generalized_time
from evidence_oid_registry import oid_name, CLAIM_EXPECTED_TAGS, KNOWN_ELEMENT_OIDS, KNOWN_CLAIM_OIDS, evidence_make_oid
 
# ---------------------------------------------------------------------------
# Dependency imports with friendly error messages
# ---------------------------------------------------------------------------
try:
    from pyasn1.type import univ, namedtype, constraint, tag, char, useful
    from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
    from pyasn1.codec.native import decoder as nat_decoder
    from pyasn1 import error as pyasn1_error
except ImportError:
    sys.exit("pyasn1 is required.  Install with:  pip install pyasn1 pyasn1-modules")
 
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, ed25519, ed448
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("WARNING: 'cryptography' package not found.  Signature verification disabled.\n"
          "         Install with:  pip install cryptography")

# ---------------------------------------------------------------------------
# ASN.1 Schema Definitions (pyasn1)
# ---------------------------------------------------------------------------
 
class ReportedClaim(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("claimType", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("value", univ.Any()),
    )
 
class ReportedClaimSeq(univ.SequenceOf):
    componentType = ReportedClaim()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))
 
class ReportedElement(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("elementType", univ.ObjectIdentifier()),
        namedtype.NamedType("claims", ReportedClaimSeq()),
    )
 
class ReportedElementSeq(univ.SequenceOf):
    componentType = ReportedElement()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))
 
class TbsEvidence(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("reportedElements", ReportedElementSeq()),
    )
 
class SignerIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "keyId",
            univ.OctetString().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType(
            "subjectPublicKeyInfo",
            univ.Any().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType(
            "certificate",
            univ.Any().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 2))),
    )
 
class SignatureBlock(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("sid", SignerIdentifier()),
        namedtype.NamedType("signatureAlgorithm", univ.Sequence()),
        namedtype.NamedType("signatureValue", univ.OctetString()),
    )
 
class SignatureBlockSeq(univ.SequenceOf):
    componentType = SignatureBlock()
 
class Evidence(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tbs", TbsEvidence()),
        namedtype.NamedType("signatures", SignatureBlockSeq()),
        namedtype.OptionalNamedType(
            "intermediateCertificates",
            univ.SequenceOf(componentType=univ.Any()).subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 0))),
    )
 
 
# ---------------------------------------------------------------------------
# Parsed Data Classes
# ---------------------------------------------------------------------------
 
@dataclass
class ParsedClaim:
    oid: str
    name: str
    raw_tag: Optional[int]
    value: Any
 
 
@dataclass
class ParsedElement:
    element_type_oid: str
    element_type_name: str
    claims: list[ParsedClaim] = field(default_factory=list)
 
 
@dataclass
class ParsedSigner:
    key_id: Optional[bytes]
    spki_der: Optional[bytes]
    cert_der: Optional[bytes]
    sig_algorithm_oid: str
    sig_algorithm_name: str
    signature_bytes: bytes
 
 
@dataclass
class ParsedEvidence:
    version: int
    elements: list[ParsedElement] = field(default_factory=list)
    signers: list[ParsedSigner] = field(default_factory=list)
    intermediate_certs_der: list[bytes] = field(default_factory=list)
    tbs_der: bytes = field(default_factory=bytes)   # DER of TbsEvidence for sig verification
 
 
# ---------------------------------------------------------------------------
# Claim value decoder
# ---------------------------------------------------------------------------
 
_ALG_OID_NAMES: dict[str, str] = {
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.113549.1.1.5":  "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.3.101.112": "id-Ed25519",
    "1.3.101.113": "id-Ed448",
}
 
def _decode_claim_value(oid_str: str, raw_any: univ.Any) -> tuple[int | None, Any]:
    """Decode the raw ANY value of a claim.  Returns (universal_tag, python_value)."""
    raw_bytes = bytes(raw_any)
    if not raw_bytes:
        return None, None
    tag_byte = raw_bytes[0]
    utag = tag_byte & 0x1F  # universal tag number (ignoring class/constructed bits)
 
    try:
        if utag == 12:  # UTF8String
            asn1_val, _ = der_decoder.decode(raw_bytes, asn1Spec=char.UTF8String())
            return utag, str(asn1_val)
        elif utag == 4:  # OCTET STRING
            asn1_val, _ = der_decoder.decode(raw_bytes, asn1Spec=univ.OctetString())
            return utag, bytes(asn1_val)
        elif utag == 2:  # INTEGER
            asn1_val, _ = der_decoder.decode(raw_bytes, asn1Spec=univ.Integer())
            return utag, int(asn1_val)
        elif utag == 1:  # BOOLEAN
            asn1_val, _ = der_decoder.decode(raw_bytes, asn1Spec=univ.Boolean())
            return utag, bool(asn1_val)
        elif utag == 24:  # GeneralizedTime
            asn1_val, _ = der_decoder.decode(raw_bytes, asn1Spec=useful.GeneralizedTime())
            return utag, str(asn1_val)
        elif utag == 16:  # SEQUENCE (KeyPurposes = SEQUENCE OF OID)
            asn1_val, _ = der_decoder.decode(
                raw_bytes,
                asn1Spec=univ.SequenceOf(componentType=univ.ObjectIdentifier()))
            return utag, [oid_name(str(o)) for o in asn1_val]
        else:
            return utag, raw_bytes.hex()
    except Exception:
        return utag, raw_bytes.hex()
 
 
# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
 
def parse_evidence(der_bytes: bytes) -> ParsedEvidence:
    """Decode DER bytes into a ParsedEvidence structure."""
    asn1_obj, remainder = der_decoder.decode(der_bytes, asn1Spec=Evidence())
    if remainder:
        raise ValueError(f"Trailing bytes after Evidence: {len(remainder)} byte(s)")
 
    tbs_asn1 = asn1_obj["tbs"]
    result = ParsedEvidence(
        version=int(tbs_asn1["version"]),
        tbs_der=der_encoder.encode(tbs_asn1),
    )
 
    # Elements + Claims
    for element in tbs_asn1["reportedElements"]:
        et_oid = str(element["elementType"])
        parsed_element = ParsedElement(
            element_type_oid=et_oid,
            element_type_name=oid_name(et_oid),
        )
        for claim in element["claims"]:
            c_oid = str(claim["claimType"])
            raw_val = claim["value"]
            tag_num, decoded = (None, None) if raw_val is None else _decode_claim_value(c_oid, raw_val)
            parsed_element.claims.append(ParsedClaim(
                oid=c_oid,
                name=oid_name(c_oid),
                raw_tag=tag_num,
                value=decoded,
            ))
        result.elements.append(parsed_element)
 
    # Signatures
    for sig_block in asn1_obj["signatures"]:
        sid = sig_block["sid"]
        key_id_val   = bytes(sid["keyId"])   if sid["keyId"].hasValue()   else None
        spki_val     = bytes(sid["subjectPublicKeyInfo"]) if sid["subjectPublicKeyInfo"].hasValue() else None
        cert_val     = bytes(sid["certificate"])         if sid["certificate"].hasValue()         else None
 
        alg_seq      = sig_block["signatureAlgorithm"]
        # First component of AlgorithmIdentifier is the OID
        alg_oid_asn1, _ = der_decoder.decode(
            der_encoder.encode(alg_seq),
            asn1Spec=univ.Sequence())
        try:
            alg_oid_str = str(alg_oid_asn1[0])
        except Exception:
            alg_oid_str = "unknown"
 
        result.signers.append(ParsedSigner(
            key_id=key_id_val,
            spki_der=spki_val,
            cert_der=cert_val,
            sig_algorithm_oid=alg_oid_str,
            sig_algorithm_name=_ALG_OID_NAMES.get(alg_oid_str, alg_oid_str),
            signature_bytes=bytes(sig_block["signatureValue"]),
        ))
 
    # Intermediate Certificates (context tag [0])
    ic = asn1_obj["intermediateCertificates"]
    if ic.hasValue():
        for cert_any in ic:
            result.intermediate_certs_der.append(bytes(cert_any))
 
    return result
 
 
# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------
 
@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sig_results: list[str] = field(default_factory=list)

def validate_evidence(ev: ParsedEvidence) -> ValidationResult:
    vr = ValidationResult(ok=True)
 
    # --- Version ---
    if ev.version != 1:
        vr.warnings.append(f"Unexpected version {ev.version} (expected 1)")
 
    # --- Elements ---
    if not ev.elements:
        vr.errors.append("TbsEvidence must have at least one ReportedElement")
 
    for i, element in enumerate(ev.elements):
        prefix = f"Element[{i}] ({element.element_type_name})"
        if element.element_type_oid not in KNOWN_ELEMENT_OIDS:
            vr.warnings.append(f"{prefix}: unknown element type OID {element.element_type_oid}")
        if not element.claims:
            vr.errors.append(f"{prefix}: must have at least one ReportedClaim")
 
        for j, claim in enumerate(element.claims):
            cp = f"{prefix} Claim[{j}] ({claim.name})"
            if claim.oid not in KNOWN_CLAIM_OIDS:
                vr.warnings.append(f"{cp}: unknown claim OID {claim.oid}")
            else:
                expected = CLAIM_EXPECTED_TAGS[claim.oid]
                if claim.raw_tag is not None and claim.raw_tag != expected:
                    vr.errors.append(
                        f"{cp}: tag mismatch — got {claim.raw_tag}, expected {expected}")
            # Validate GeneralizedTime format
            if claim.raw_tag == 24 and isinstance(claim.value, str):
                validation_result = validate_generalized_time(claim.value)
                if not validation_result:
                    vr.errors.append(f"{cp}: invalid GeneralizedTime '{claim.value}'")
            # Validate fipslevel range (0–4)
            if claim.name == "platform-fipslevel" and isinstance(claim.value, int):
                if not (0 <= claim.value <= 4):
                    vr.warnings.append(f"{cp}: fipslevel {claim.value} outside [0,4]")
 
    # --- Signatures ---
    if not ev.signers:
        vr.warnings.append("No signatures present")
 
    for i, signer in enumerate(ev.signers):
        sp = f"Signature[{i}]"
        has_id = sum([
            signer.key_id is not None,
            signer.spki_der is not None,
            signer.cert_der is not None,
        ])
        if has_id == 0:
            vr.errors.append(f"{sp}: SignerIdentifier must supply keyId, spki, or certificate")
        if has_id > 1:
            vr.warnings.append(f"{sp}: multiple SignerIdentifier fields set (only first used)")
 
        if not signer.signature_bytes:
            vr.errors.append(f"{sp}: empty signatureValue")
 
        # Signature verification
        if HAS_CRYPTO and signer.spki_der is not None:
            sig_ok, msg = _verify_signature(ev.tbs_der, signer)
            vr.sig_results.append(f"{sp}: {msg}")
            if not sig_ok:
                vr.errors.append(f"{sp}: signature verification FAILED — {msg}")
        elif signer.spki_der is None and signer.cert_der is None:
            vr.sig_results.append(f"{sp}: skipped (no public key material in SignerIdentifier)")
        elif not HAS_CRYPTO:
            vr.sig_results.append(f"{sp}: skipped (cryptography library not available)")
 
    vr.ok = len(vr.errors) == 0
    return vr
 
 
# ---------------------------------------------------------------------------
# Signature verification (cryptography library)
# ---------------------------------------------------------------------------
 
def _verify_signature(tbs_der: bytes, signer: ParsedSigner) -> tuple[bool, str]:
    """Attempt to verify a signature over TbsEvidence DER using the embedded SPKI."""
    alg = signer.sig_algorithm_name.lower()
    try:
        pub_key = serialization.load_der_public_key(signer.spki_der)
    except Exception as exc:
        return False, f"cannot load public key: {exc}"
 
    sig = signer.signature_bytes
    try:
        if "ecdsa" in alg or "ec" in alg:
            h = _hash_for_alg(alg)
            pub_key.verify(sig, tbs_der, ec.ECDSA(h))
            return True, f"ECDSA OK ({signer.sig_algorithm_name})"
        elif "rsa" in alg:
            h = _hash_for_alg(alg)
            pub_key.verify(sig, tbs_der, padding.PKCS1v15(), h)
            return True, f"RSA PKCS1v15 OK ({signer.sig_algorithm_name})"
        elif "ed25519" in alg:
            pub_key.verify(sig, tbs_der)
            return True, "Ed25519 OK"
        elif "ed448" in alg:
            pub_key.verify(sig, tbs_der)
            return True, "Ed448 OK"
        else:
            return False, f"unsupported algorithm: {signer.sig_algorithm_name}"
    except InvalidSignature:
        return False, "invalid signature"
    except Exception as exc:
        return False, str(exc)
 
 
def _hash_for_alg(alg: str) -> hashes.HashAlgorithm:
    if "512" in alg:
        return hashes.SHA512()
    elif "384" in alg:
        return hashes.SHA384()
    else:
        return hashes.SHA256()
 
 
# ---------------------------------------------------------------------------
# Pretty Printer
# ---------------------------------------------------------------------------
 
def _indent(text: str, n: int = 2) -> str:
    return textwrap.indent(text, " " * n)
 
 
def _fmt_value(v: Any) -> str:
    if isinstance(v, bytes):
        return f"0x{v.hex()}"
    if isinstance(v, list):
        return "[" + ", ".join(str(x) for x in v) + "]"
    return str(v)
 
 
def print_evidence(ev: ParsedEvidence) -> None:
    print("=" * 60)
    print(f"  PKIX-Evidence-2025  (version {ev.version})")
    print("=" * 60)
    print(f"TbsEvidence DER fingerprint (SHA-256): "
          f"{hashlib.sha256(ev.tbs_der).hexdigest()[:16]}…")
    print()
 
    for i, element in enumerate(ev.elements):
        print(f"  Element [{i}]: {element.element_type_name}  ({element.element_type_oid})")
        for claim in element.claims:
            tag_str = f"[tag={claim.raw_tag}]" if claim.raw_tag is not None else ""
            print(f"    • {claim.name:<35s} {tag_str:<10s} = {_fmt_value(claim.value)}")
        print()
 
    print(f"  Signatures ({len(ev.signers)}):")
    for i, sig in enumerate(ev.signers):
        print(f"    [{i}] algorithm: {sig.sig_algorithm_name}")
        if sig.key_id:
            print(f"        key-id  : 0x{sig.key_id.hex()}")
        if sig.spki_der:
            fp = hashlib.sha256(sig.spki_der).hexdigest()[:16]
            print(f"        spki    : SHA-256={fp}…")
        if sig.cert_der:
            fp = hashlib.sha256(sig.cert_der).hexdigest()[:16]
            print(f"        cert    : SHA-256={fp}…")
        print(f"        sig     : 0x{sig.signature_bytes.hex()[:32]}… "
              f"({len(sig.signature_bytes)} bytes)")
 
    if ev.intermediate_certs_der:
        print(f"\n  Intermediate Certificates ({len(ev.intermediate_certs_der)}):")
        for i, c in enumerate(ev.intermediate_certs_der):
            print(f"    [{i}] {len(c)} bytes")
    print()
 
 
def print_validation(vr: ValidationResult) -> None:
    status = "✓ VALID" if vr.ok else "✗ INVALID"
    print(f"Validation: {status}")
    for e in vr.errors:
        print(f"  [ERROR]   {e}")
    for w in vr.warnings:
        print(f"  [WARN]    {w}")
    for s in vr.sig_results:
        print(f"  [SIG]     {s}")
    if not vr.errors and not vr.warnings and not vr.sig_results:
        print("  (no issues found)")
    print()
 
 
# ---------------------------------------------------------------------------
# Builder helpers (for testing / generating sample data)
# ---------------------------------------------------------------------------
 
def _encode_utf8(s: str) -> bytes:
    v = char.UTF8String(s)
    return der_encoder.encode(v)
 
def _encode_octet(b: bytes) -> bytes:
    return der_encoder.encode(univ.OctetString(b))
 
def _encode_int(n: int) -> bytes:
    return der_encoder.encode(univ.Integer(n))
 
def _encode_bool(b: bool) -> bytes:
    return der_encoder.encode(univ.Boolean(b))
 
def _encode_generalizedtime(dt: datetime) -> bytes:
    s = dt.strftime("%Y%m%d%H%M%SZ")
    return der_encoder.encode(useful.GeneralizedTime(s))
 
 
def build_sample_evidence_der(
    nonce: bytes = b"\xde\xad\xbe\xef",
    vendor: str = "ACME Corp",
    hw_model: bytes = b"\x00\x01",
    hw_serial: str = "SN-12345678",
    sw_name: str = "FirmwareX",
    sw_version: str = "3.1.4",
    key_identifier: str = "mykey-001",
    key_extractable: bool = False,
    key_sensitive: bool = True,
) -> bytes:
    """Build a minimal (unsigned) Evidence DER for testing."""
 
    def make_claim(oid_str: str, value_der: bytes) -> ReportedClaim:
        c = ReportedClaim()
        c["claimType"] = evidence_make_oid(oid_str)
        c["value"] = univ.Any(hexValue=value_der.hex())
        return c
 
    # ---- Transaction element ----
    tx_element = ReportedElement()
    tx_element["elementType"] = evidence_make_oid("transaction")
    tx_claims = ReportedClaimSeq()
    tx_claims[0] = make_claim("transaction-nonce", _encode_octet(nonce))
    tx_claims[1] = make_claim("transaction-timestamp",
                               _encode_generalizedtime(datetime.now(timezone.utc)))
    tx_element["claims"] = tx_claims
 
    # ---- Platform element ----
    pl_element = ReportedElement()
    pl_element["elementType"] = evidence_make_oid("platform")
    pl_claims = ReportedClaimSeq()
    pl_claims[0] = make_claim("platform-vendor", _encode_utf8(vendor))
    pl_claims[1] = make_claim("platform-hwmodel", _encode_octet(hw_model))
    pl_claims[2] = make_claim("platform-hwserial", _encode_utf8(hw_serial))
    pl_claims[3] = make_claim("platform-swname", _encode_utf8(sw_name))
    pl_claims[4] = make_claim("platform-swversion", _encode_utf8(sw_version))
    pl_claims[5] = make_claim("platform-fipsboot", _encode_bool(False))  # fipsboot
    pl_element["claims"] = pl_claims
 
    # ---- Key element ----
    key_element = ReportedElement()
    key_element["elementType"] = evidence_make_oid("key")
    key_claims = ReportedClaimSeq()
    key_claims[0] = make_claim("key-identifier", _encode_utf8(key_identifier))
    key_claims[1] = make_claim("key-extractable", _encode_bool(key_extractable))
    key_claims[2] = make_claim("key-sensitive", _encode_bool(key_sensitive))
    key_claims[3] = make_claim("key-never-extractable", _encode_bool(True))  # never-extractable
    key_claims[4] = make_claim("key-local", _encode_bool(True))  # local
    # Key purpose: sign + verify
    kp_seq = univ.SequenceOf(componentType=univ.ObjectIdentifier())
    kp_seq[0] = evidence_make_oid("capability-sign")  # sign
    kp_seq[1] = evidence_make_oid("capability-verify")  # verify
    key_claims[5] = make_claim("key-purpose", der_encoder.encode(kp_seq))
    key_element["claims"] = key_claims
 
    # ---- TbsEvidence ----
    tbs = TbsEvidence()
    tbs["version"] = 1
    elements = ReportedElementSeq()
    elements[0] = tx_element
    elements[1] = pl_element
    elements[2] = key_element
    tbs["reportedElements"] = elements
 
    # ---- Evidence (no signatures for sample) ----
    ev = Evidence()
    ev["tbs"] = tbs
    ev["signatures"] = SignatureBlockSeq()
 
    return der_encoder.encode(ev)
 
 
# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
 
def main() -> None:
    import argparse, os
 
    parser = argparse.ArgumentParser(
        description="Parse and verify PKIX-Evidence-2025 DER files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          # Generate a sample DER file and validate it
          python pkix_evidence_2025.py --sample --out sample.der
          python pkix_evidence_2025.py sample.der
 
          # Validate only (no pretty print)
          python pkix_evidence_2025.py sample.der --quiet
        """),
    )
    parser.add_argument("input", nargs="?", help="DER-encoded Evidence file to parse")
    parser.add_argument("--sample", action="store_true",
                        help="Generate and parse a built-in sample Evidence blob")
    parser.add_argument("--out", metavar="FILE",
                        help="Write DER bytes to FILE (use with --sample)")
    parser.add_argument("--quiet", action="store_true",
                        help="Only print validation result, not the full structure")
    args = parser.parse_args()
 
    if args.sample:
        print("Generating sample Evidence DER …")
        der = build_sample_evidence_der()
        if args.out:
            with open(args.out, "wb") as f:
                f.write(der)
            print(f"Written to {args.out}\n")
    elif args.input:
        with open(args.input, "rb") as f:
            der = f.read()
        print(f"Read {len(der)} bytes from {args.input}\n")
    else:
        parser.print_help()
        print("\nNo input given — running built-in sample demo.\n")
        der = build_sample_evidence_der()
 
    try:
        ev = parse_evidence(der)
    except Exception as exc:
        print(f"[FATAL] Parsing failed: {exc}")
        raise SystemExit(1)
 
    if not args.quiet:
        print_evidence(ev)
 
    vr = validate_evidence(ev)
    print_validation(vr)
    raise SystemExit(0 if vr.ok else 1)
 
 
if __name__ == "__main__":
    main()
    