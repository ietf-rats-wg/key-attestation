import sys
import textwrap
import cryptography
from cryptography.x509.verification import PolicyBuilder, Store
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurveSignatureAlgorithm
from pyasn1.type.univ import ObjectIdentifier

import create_ak
from pkix_evidence import *

BASE_DIR = Path(__file__).resolve().parent
SAMPLEDATA_DIR = BASE_DIR.parent / "sampledata"

# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _fmt_oid(o: univ.ObjectIdentifier) -> str:
    """Return a human-readable name for an OID, falling back to dotted string."""
    dotted = ".".join(str(arc) for arc in o)
    return OID_NAMES.get(dotted, dotted)

def _decode_claim_value(raw_any: univ.Any) -> tuple[int | None, Any]:
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

def validate_evidence(data: bytes, ak_cert: x509.Certificate, int_cert: x509.Certificate=None, ca_cert: x509.Certificate=None) -> bool: # todo-- add certs
    # First, validate the cert chain
    if ca_cert is not None:
        # skipping this for the moment because apparently python cryptography's x.509 validator now only supports TLS certs
        # and not generic certs
        # https://cryptography.io/en/latest/x509/verification/
        # Maybe the right answer is to use the openssl module for python to validate the cert chain?
        # sample code here:
        # https://stackoverflow.com/a/30719888
        # TODO
        pass

    # Check that the ak_cert contains the id-kp-attestationKey
    try:
        eku = ak_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE).value
    except:
        print("ExtendedKeyUsage missing on AK cert", file=sys.stderr)
        return False

    # "the EKU certificate extension MUST include the id-kp-attestationKey"
    if len(eku) == 0:
        print("ExtendedKeyUsage is empty on AK cert", file=sys.stderr)
        return False
    found_id_kp_attestation = False
    for eku_val in eku:
        if eku_val == id_kp_attest_oid:
            found_id_kp_attestation = True

    if not found_id_kp_attestation:
        print("ExtendedKeyUsage on AK cert does not contain id_kp_attestation ("+id_kp_attest_oid.dotted_string+")", file=sys.stderr)
        return False

    # the KeyUsage extension (KU) MUST have the digitalSignature bit set.
    try:
        ku = ak_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE).value
        if not ku.digital_signature:
            print("KeyUsage does not assert digitalSignature", file=sys.stderr)
            return False
    except:
        print("KeyUsage missing on AK cert", file=sys.stderr)
        return False


    # Now validate the signature on the Evidence
    ev = decode_evidence(data)
    signatureBlockSeq = ev.components[1] # SignatureBlockSeq
    for signatureBlock in signatureBlockSeq:
        signatureAlgID = signatureBlock.components[1].components[0]
        signatureValue = signatureBlock.components[2].asOctets()

        # binary value to be validated
        tbs = ev.components[0]
        tbs_bytes = der_encoder.encode(tbs)

        # TODO: Surely there is a generic way to get python to just verify any signature for any alg it recognizes
        if signatureAlgID == univ.ObjectIdentifier(x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256.dotted_string):
            try:
                pk = ak_cert.public_key()
                ak_cert.public_key().verify(
                    signatureValue,
                    tbs_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
            except cryptography.exceptions.InvalidSignature:
                print("Signature verification failed on Evidence", file=sys.stderr)
                return False
        else:
            print("Signature algorithm not supported", file=sys.stderr)
            return False

    return True

def read_evidence_file(file):
    """Reads the evidence from file, accepts either PEM with the -----BEGIN EVIDENCE---- header, or raw DER"""
    input = open(args.input, "rb").read()

    # first, try it as raw DER
    try:
        ev = der_decoder.decode(input)
        return ev
    except:
        # nothing, keep going
        pass

    # Then try it as PEM
    input = str(input)
    if input.startswith("-----BEGIN EVIDENCE-----"):
        input = input[24:]

    if input.endswith("-----END EVIDENCE-----"):
        input = input[:-24]

    try:
        ev = der_decoder.decode(base64.decode(input))
    except:
        print("ERROR: input file could not be parsed as DER or as PEM.", file=sys.stderr)
        exit(-1)

    return ev

def pretty_print_evidence(ev: Evidence, indent: int = 0) -> [str]:
    """Recursively print an Evidence structure to stdout."""

    strs_out = []

    pad = "  " * indent
    tbs = ev["tbs"]
    strs_out.append(f"{pad}Evidence:")
    strs_out.append(f"{pad}  TbsEvidence:")
    strs_out.append(f"{pad}    version: {int(tbs['version'])}")

    for i, element in enumerate(tbs["reportedElements"]):
        strs_out.append(f"{pad}    ReportedElement[{i}]: {_fmt_oid(element['elementType'])}")
        for j, claim in enumerate(element["claims"]):
            ct = _fmt_oid(claim["claimType"])
            cv = claim["value"]
            if cv.hasValue():
                tag_num, decoded = _decode_claim_value(cv)
                chosen = "unknown"
                if 4 == tag_num:
                    chosen = "OCTET STRING"
                    val = decoded.hex()
                    if len(val) > 24:
                        val = val[:24] + '...'
                elif 1 == tag_num:
                    chosen = "BOOLEAN"
                    val = decoded
                elif 2 == tag_num:
                    chosen = "INTEGER"
                    val = decoded
                elif 12 == tag_num:
                    chosen = "UTF8String"
                    val = decoded
                    if len(val) > 24:
                        val = val[:24] + '...'
                elif 24 == tag_num:
                    chosen = "GeneralizedTime"
                    val = decoded
                elif 16 == tag_num and "id-evidence-claim-key-purpose" == ct:
                    chosen = "KeyPurposes"
                    val = ",".join(decoded)
                else:
                    val = str(decoded)
                strs_out.append(f"{pad}      Claim[{j}]: {ct}")
                strs_out.append(f"{pad}              -> [{chosen}] {val}")
            else:
                strs_out.append(f"{pad}      Claim[{j}]: {ct}  (no value)")

    strs_out.append(f"{pad}  Signatures ({len(ev['signatures'])}):")
    for i, sig in enumerate(ev["signatures"]):
        sid = sig["sid"]
        alg = _fmt_oid(sig["signatureAlgorithm"]["algorithm"])
        sv  = bytes(sig["signatureValue"]).hex()
        if len(sv) > 24:
            sv = sv[:24] + '...'
        strs_out.append(f"{pad}    SignatureBlock[{i}]:")
        strs_out.append(f"{pad}      algorithm      : {alg}")
        strs_out.append(f"{pad}      signatureValue : {sv[:48]}{'...' if len(sv) > 48 else ''}")
        if sid["keyId"].hasValue():
            strs_out.append(f"{pad}      keyId          : {bytes(sid['keyId']).hex()}")
        if sid["subjectPublicKeyInfo"].hasValue():
            spki_alg = _fmt_oid(
                sid["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
            )
            strs_out.append(f"{pad}      SPKI algorithm : {spki_alg}")
        if sid["certificate"].hasValue():
            strs_out.append(f"{pad}      AK Certificate : present")

    if ev["intermediateCertificates"].hasValue():
        strs_out.append(f"{pad}  Intermediate Certificates:  ({len(ev['intermediateCertificates'])})")

    return strs_out


def _encode_generalizedtime(dt: datetime) -> bytes:
    return dt.strftime("%Y%m%d%H%M%SZ")

# ---------------------------------------------------------------------------
# Main — end-to-end DER round-trip demonstration
# ---------------------------------------------------------------------------

def build_example1(ak_private_key: ec.EllipticCurvePrivateKey, ak_cert: x509.Certificate, int_cert: x509.Certificate) -> bytes:
    """
    This example shows a minimal PKIX Evidence object with only transaction and platform entities a single signature where the AK key is identified only by
    its SHA1 hash KeyID.
    """
    ev = PkixEvidence()

    # Transaction element
    tx_claims = ReportedClaimSeq()
    tx_claims[0] = make_claim(
        "id-evidence-claim-transaction-nonce",
        b"\xde\xad\xbe\xef\xca\xfe\xba\xbe",
    )
    tx_claims[1] = make_claim(
        "id-evidence-claim-transaction-timestamp",
        _encode_generalizedtime(datetime.now(timezone.utc)) )

    ak_public_key_der = ak_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tx_claims[2] = make_claim("id-evidence-claim-transaction-ak-spki", ak_public_key_der)

    tx_element = ReportedElement()
    tx_element["elementType"] = evidence_make_oid("id-evidence-element-transaction")
    tx_element["claims"] = tx_claims

    ev.add_element(tx_element)


    # Platform element
    plat_claims = ReportedClaimSeq()
    plat_claims[0] = make_claim("id-evidence-claim-platform-vendor",    "Acme Corp")
    plat_claims[1] = make_claim("id-evidence-claim-platform-hwmodel",   "HSM-9000".encode('utf-8'))
    plat_claims[2] = make_claim("id-evidence-claim-platform-hwversion", "2.1.0")
    plat_claims[3] = make_claim("id-evidence-claim-platform-fipsboot",  True)
    plat_claims[4] = make_claim("id-evidence-claim-platform-fipslevel", 3)
    plat_claims[5] = make_claim("id-evidence-claim-platform-uptime",    86400)

    plat_element = ReportedElement()
    plat_element["elementType"] = evidence_make_oid("id-evidence-element-platform")
    plat_element["claims"]     = plat_claims

    ev.add_element(plat_element)

    return ev.sign_and_encode(ak_cert, ak_private_key, int_cert, includeCerts=False)



def build_example2(ak_private_key: ec.EllipticCurvePrivateKey, ak_cert: x509.Certificate, int_cert: x509.Certificate) -> bytes:
    """
    This example shows a PKIX Evidence object that is attesting an application key held within the HSM.
    For the purposes of this example, the Platform Entity is kept short.
    This example embeds the AK and Intermediate CA certificates in the Evidence object. It chains to the same root as above.
    """
    ev = PkixEvidence()

    # Transaction element
    tx_claims = ReportedClaimSeq()
    tx_claims[0] = make_claim(
        "id-evidence-claim-transaction-nonce",
        b"\xbe\xef\xca\xfe\xba\xbe\xde\xad",
    )
    tx_claims[1] = make_claim(
        "id-evidence-claim-transaction-timestamp",
        _encode_generalizedtime(datetime.now(timezone.utc)))

    tx_element = ReportedElement()
    tx_element["elementType"] = evidence_make_oid("id-evidence-element-transaction")
    tx_element["claims"] = tx_claims

    ak_public_key_der = ak_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tx_claims[2] = make_claim("id-evidence-claim-transaction-ak-spki", ak_public_key_der)

    tx_element = ReportedElement()
    tx_element["elementType"] = evidence_make_oid("id-evidence-element-transaction")
    tx_element["claims"]     = tx_claims

    ev.add_element(tx_element)


    # Platform element
    plat_claims = ReportedClaimSeq()
    plat_claims.append(make_claim("id-evidence-claim-platform-hwmodel",   "HSM-9000".encode('utf-8')))

    plat_element = ReportedElement()
    plat_element["elementType"] = evidence_make_oid("id-evidence-element-platform")
    plat_element["claims"]     = plat_claims

    ev.add_element(plat_element)


    # Key element 1
    private_key = create_ak.generate_ec_key()

    key_claims = ReportedClaimSeq()
    key_claims.append(make_claim(
        "id-evidence-claim-key-identifier",
        "9a25f603-a2c4-4dad-9ee0-a1b4e771f2c3",
    ))
    key_claims.append(make_claim(
        "id-evidence-claim-key-spki",
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    ))
    key_claims.append(make_claim("id-evidence-claim-key-extractable",       False))
    key_claims.append(make_claim("id-evidence-claim-key-never-extractable", True))
    key_claims.append(make_claim("id-evidence-claim-key-sensitive",         True))
    key_claims.append(make_claim("id-evidence-claim-key-local",             True))
    key_claims.append(make_claim(
        "id-evidence-claim-key-purpose",
        [
            "id-evidence-key-capability-sign"
        ],
    ))

    key_element = ReportedElement()
    key_element["elementType"] = evidence_make_oid("id-evidence-element-key")
    key_element["claims"]     = key_claims

    ev.add_element(key_element)


    # Key element 2
    private_key = create_ak.generate_ec_key()

    key_claims = ReportedClaimSeq()
    key_claims.append(make_claim(
        "id-evidence-claim-key-identifier",
        "85704b99-7097-4bca-93b6-13352f865ace",
    ))
    key_claims.append(make_claim(
        "id-evidence-claim-key-spki",
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    ))
    key_claims.append(make_claim("id-evidence-claim-key-extractable",       True))
    key_claims.append(make_claim("id-evidence-claim-key-sensitive",         False))

    key_element = ReportedElement()
    key_element["elementType"] = evidence_make_oid("id-evidence-element-key")
    key_element["claims"]     = key_claims

    ev.add_element(key_element)

    return ev.sign_and_encode(ak_cert, ak_private_key, int_cert)

def write_b64_and_pem(file_basename: Path, data: bytes):
    # write Base64
    with open(file_basename.with_suffix('.b64'), "w") as f:
        f.write(base64.b64encode(data).decode("ascii"))

    # write PEM
    with open(file_basename.with_suffix('.pem'), "w") as f:
        f.write("-----BEGIN EVIDENCE-----\n")
        for line in textwrap.wrap(
                base64.b64encode(data).decode("ascii"),
                width=68, replace_whitespace=False,
                drop_whitespace=False):
            f.write(line+'\n')
        f.write("-----END EVIDENCE-----\n")

def write_pretty_print(file_basename: Path, data: bytes):
    with open(file_basename.with_suffix('.pp'), "w") as f:
        for line in pretty_print_evidence(decode_evidence(data)):
            f.write(line+'\n')

def generate_samples():
    # generate AK key and cert chain
    ak_private_key, ak_cert, int_cert, ca_cert, ca_private_key = create_ak.generateAndSaveCerts()

    # Build Example 1
    ev1_der = build_example1(ak_private_key, ak_cert, int_cert)
    if not validate_evidence(ev1_der, ak_cert, int_cert, ca_cert):
        print("Evidence failed to validate", file=sys.stderr)
    write_b64_and_pem(SAMPLEDATA_DIR / "evidence1", ev1_der)
    write_pretty_print(SAMPLEDATA_DIR / "evidence1", ev1_der)

    # Build Example 2
    ev2_der = build_example2(ak_private_key, ak_cert, int_cert)
    if not validate_evidence(ev2_der, ak_cert, int_cert, ca_cert):
        print("Evidence failed to validate", file=sys.stderr)
    write_b64_and_pem(SAMPLEDATA_DIR / "evidence2", ev2_der)
    write_pretty_print(SAMPLEDATA_DIR / "evidence2", ev2_der)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="""Parse and verify PKIX-Evidence-2025 DER files
        Examples:
          # Generate a sample DER files to the sampledata/ dir
          python src/main.py --generate

          # Validate only (no pretty print)
          python src/main.py --validate sample.der ak.ctr [int_ca.crt] [ca.crt] --quiet
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          # Generate a sample DER files to the sampledata/ dir
          python src/main.py --generate

          # Validate only (no pretty print)
          python src/main.py --validate sample.der ak.ctr [int_ca.crt] [ca.crt] --quiet
        """),
    )

    parser.add_argument("input", nargs="?", help="DER-encoded Evidence file to parse")
    parser.add_argument("ak_cert", nargs="?", help="X.509 certificate file for the AK certificate. Mandatory for verification.")
    parser.add_argument("int_cert", nargs="?", help="X.509 certificate file for the intermediate certificate. Optional.")
    parser.add_argument("ca_cert", nargs="?", help="X.509 certificate file for the root certificate. Optional.")
    parser.add_argument("--generate", action="store_true",
                        help="Generate and parse a built-in sample Evidence blob")
    parser.add_argument("--validate", action="store_true",
                        help="Validate a sample Evidence blob")
    parser.add_argument("--quiet", action="store_true",
                        help="Only print validation result, not the full structure")
    parser.add_argument("--prettyprint", action="store_true",
                        help="Only pretty print the contents; do not validate")

    args = parser.parse_args()


    if args.generate:
        print("Generating sample Evidence DER to sampledata/ …")
        generate_samples()
    elif args.validate:
        if args.input is None:
            print("ERROR: input file not provided", file=sys.stderr)
            exit(-1)
        else:
            input = open(args.input, "rb").read()

        if args.ak_cert is None:
            print("ERROR: ak_cert file not provided", file=sys.stderr)
            exit(-1)
        else:
            ak_cert = open(args.ak_cert, "rb").read()

        if args.int_cert is None:
            int_cert = None
        else:
            int_cert = open(args.int_cert, "rb").read()

        if args.ca_cert is None:
            ca_cert = None
        else:
            ca_cert = open(args.ca_cert, "rb").read()

        # do the validation
        if validate_evidence(input, ak_cert, int_cert, ca_cert):
            print("Evidence validation successful")
        else:
            print("Evidence validation failed", file=sys.stderr)
            exit(-1)

        if not args.quiet:
            try:
                pretty_print_evidence(der_decoder.decode(input))
            except:
                print("Evidence failed to parse", file=sys.stderr)
                exit(-1)
    elif args.prettyprint:

        if args.input is None:
            print("ERROR: input file not provided", file=sys.stderr)
            exit(-1)
        else:
            input = open(args.input, "rb").read()
            try:
                pretty_print_evidence(der_decoder.decode(input))
            except:
                print("Evidence failed to parse", file=sys.stderr)
                exit(-1)
    else:
        parser.print_help()


