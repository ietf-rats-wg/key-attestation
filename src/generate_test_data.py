import textwrap

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


def pretty_print_evidence(ev: Evidence, indent: int = 0) -> [str]:
    """Recursively print an Evidence structure to stdout."""

    strs_out = []

    pad = "  " * indent
    tbs = ev["tbs"]
    strs_out.append(f"{pad}Evidence:")
    strs_out.append(f"{pad}  TbsEvidence:")
    strs_out.append(f"{pad}    version: {int(tbs['version'])}")

    for i, entity in enumerate(tbs["reportedEntities"]):
        strs_out.append(f"{pad}    ReportedEntity[{i}]: {_fmt_oid(entity['entityType'])}")
        for j, claim in enumerate(entity["claims"]):
            ct = _fmt_oid(claim["claimType"])
            cv = claim["value"]
            if cv.hasValue():
                chosen = cv.getName()
                if chosen == "bytes":
                    val = bytes(cv["bytes"]).hex()
                    if len(val) > 24:
                        val = val[:24] + '...'
                else:
                    val    = cv.getComponent()
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

# ---------------------------------------------------------------------------
# Main — end-to-end DER round-trip demonstration
# ---------------------------------------------------------------------------

def build_example1(ak_private_key: ec.EllipticCurvePrivateKey, ak_cert: x509.Certificate, int_cert: x509.Certificate) -> bytes:
    """
    This example shows a minimal PKIX Evidence object with only transaction and platform entities a single signature where the AK key is identified only by
    its SHA1 hash KeyID.
    """
    ev = PkixEvidence()

    # Transaction entity
    tx_claims = ReportedClaimSeq()
    tx_claims[0] = make_claim(
        "id-evidence-claim-transaction-nonce",
        b"\xde\xad\xbe\xef\xca\xfe\xba\xbe",
    )
    tx_claims[1] = ReportedClaim()
    tx_claims[1]["claimType"] = mkoid("id-evidence-claim-transaction-timestamp")
    tx_claims[1]["value"] = make_claim_value_time("20250314120000Z")

    tx_entity = ReportedEntity()
    tx_entity["entityType"] = mkoid("id-evidence-entity-transaction")
    tx_entity["claims"] = tx_claims

    ak_public_key_der = ak_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tx_claims[2] = make_claim("id-evidence-claim-transaction-ak-spki", ak_public_key_der)

    tx_entity = ReportedEntity()
    tx_entity["entityType"] = mkoid("id-evidence-entity-transaction")
    tx_entity["claims"]     = tx_claims

    ev.add_entity(tx_entity)


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

    ev.add_entity(plat_entity)

    return ev.sign_and_encode(ak_cert, ak_private_key, int_cert, includeCerts=False)



def build_example2(ak_private_key: ec.EllipticCurvePrivateKey, ak_cert: x509.Certificate, int_cert: x509.Certificate) -> bytes:
    """
    This example shows a PKIX Evidence object that is attesting an application key held within the HSM.
    For the purposes of this example, the Platform Entity is kept short.
    This example embeds the AK and Intermediate CA certificates in the Evidence object. It chains to the same root as above.
    """
    ev = PkixEvidence()

    # Transaction entity
    tx_claims = ReportedClaimSeq()
    tx_claims[0] = make_claim(
        "id-evidence-claim-transaction-nonce",
        b"\xbe\xef\xca\xfe\xba\xbe\xde\xad",
    )
    tx_claims[1] = ReportedClaim()
    tx_claims[1]["claimType"] = mkoid("id-evidence-claim-transaction-timestamp")
    tx_claims[1]["value"] = make_claim_value_time("20250314120000Z")

    tx_entity = ReportedEntity()
    tx_entity["entityType"] = mkoid("id-evidence-entity-transaction")
    tx_entity["claims"] = tx_claims

    ak_public_key_der = ak_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tx_claims[2] = make_claim("id-evidence-claim-transaction-ak-spki", ak_public_key_der)

    tx_entity = ReportedEntity()
    tx_entity["entityType"] = mkoid("id-evidence-entity-transaction")
    tx_entity["claims"]     = tx_claims

    ev.add_entity(tx_entity)


    # Platform entity
    plat_claims = ReportedClaimSeq()
    plat_claims.append(make_claim("id-evidence-claim-platform-hwmodel",   "HSM-9000"))

    plat_entity = ReportedEntity()
    plat_entity["entityType"] = mkoid("id-evidence-entity-platform")
    plat_entity["claims"]     = plat_claims

    ev.add_entity(plat_entity)


    # Key entity 1
    private_key = create_ak.generate_ec_key()

    key_claims = ReportedClaimSeq()
    key_claims.append(make_claim(
        "id-evidence-claim-key-identifier",
        "key-001",
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
        encode_key_capabilities(build_example_key_capabilities()),
    ))

    key_entity = ReportedEntity()
    key_entity["entityType"] = mkoid("id-evidence-entity-key")
    key_entity["claims"]     = key_claims

    ev.add_entity(key_entity)


    # Key entity 2
    private_key = create_ak.generate_ec_key()

    key_claims = ReportedClaimSeq()
    key_claims.append(make_claim(
        "id-evidence-claim-key-identifier",
        "key-002",
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

    key_entity = ReportedEntity()
    key_entity["entityType"] = mkoid("id-evidence-entity-key")
    key_entity["claims"]     = key_claims

    ev.add_entity(key_entity)

    return ev.sign_and_encode(ak_cert, ak_private_key, int_cert)



def build_example3(ak_private_key: ec.EllipticCurvePrivateKey,
                   ak_cert: x509.Certificate,
                   int_cert: x509.Certificate,
                   ca_private_key: ec.EllipticCurvePrivateKey,
                   ca_cert: x509.Certificate) -> bytes:
    """
    To exercise fuller functionality of the PKIX Evidence object, this example shows how a vendor might represent a multi-tenant HSM architecture.
    """

    # First, generate a second Int and AK from the same root
    tenant_int_private_key, tenant_int_cert = create_ak.create_int_ca(ca_private_key, ca_cert, "tenant_int.crt", cn="TenantsCA")
    tenant_ak_private_key, tenant_ak_cert = create_ak.create_end_entity_cert(tenant_int_private_key, tenant_int_cert, "tenant_ak.crt", cn="tenant001 AK")

    ev = PkixEvidence()

    # Transaction entity
    tx_claims = ReportedClaimSeq()
    tx_claims[0] = make_claim(
        "id-evidence-claim-transaction-nonce",
        b"\xca\xfe\xba\xbe\xde\xad\xbe\xef",
    )
    tx_claims[1] = ReportedClaim()
    tx_claims[1]["claimType"] = mkoid("id-evidence-claim-transaction-timestamp")
    tx_claims[1]["value"] = make_claim_value_time("20250314120000Z")

    tx_entity = ReportedEntity()
    tx_entity["entityType"] = mkoid("id-evidence-entity-transaction")
    tx_entity["claims"] = tx_claims

    ak_public_key_der = ak_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tx_claims[2] = make_claim("id-evidence-claim-transaction-ak-spki", ak_public_key_der)

    tenant_ak_public_key_der = tenant_ak_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tx_claims[3] = make_claim("id-evidence-claim-transaction-ak-spki", tenant_ak_public_key_der)

    tx_entity = ReportedEntity()
    tx_entity["entityType"] = mkoid("id-evidence-entity-transaction")
    tx_entity["claims"]     = tx_claims

    ev.add_entity(tx_entity)


    # Platform entity
    plat_claims = ReportedClaimSeq()
    plat_claims.append(make_claim("id-evidence-claim-platform-hwmodel",   "HSM-9000"))

    plat_entity = ReportedEntity()
    plat_entity["entityType"] = mkoid("id-evidence-entity-platform")
    plat_entity["claims"]     = plat_claims

    ev.add_entity(plat_entity)

    plat_claims = ReportedClaimSeq()
    plat_claims.append(make_claim("id-evidence-claim-platform-vendor",   "BigCloudCorp Tenant Management System"))
    plat_claims.append(make_claim("id-evidence-claim-platform-swname",   "tenant-001"))

    plat_entity = ReportedEntity()
    plat_entity["entityType"] = mkoid("id-evidence-entity-platform")
    plat_entity["claims"]     = plat_claims

    ev.add_entity(plat_entity)


    # Key entity
    private_key = create_ak.generate_ec_key()

    key_claims = ReportedClaimSeq()
    key_claims.append(make_claim(
        "id-evidence-claim-key-identifier",
        "key-001",
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
        encode_key_capabilities(build_example_key_capabilities()),
    ))

    key_entity = ReportedEntity()
    key_entity["entityType"] = mkoid("id-evidence-entity-key")
    key_entity["claims"]     = key_claims

    ev.add_entity(key_entity)

    ev.sign_and_encode(ak_cert, ak_private_key, int_cert)
    ev.sign_and_encode(tenant_ak_cert, tenant_ak_private_key, tenant_int_cert)

    int_certs = [int_cert, tenant_int_cert]
    return ev.encode(int_certs)



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

if __name__ == "__main__":
    # generate AK key and cert chain
    ak_private_key, ak_cert, int_cert, ca_cert, ca_private_key = create_ak.generateAndSaveCerts()

    # Build Example 1
    ev1_der = build_example1(ak_private_key, ak_cert, int_cert)
    write_b64_and_pem(SAMPLEDATA_DIR / "evidence1", ev1_der)
    write_pretty_print(SAMPLEDATA_DIR / "evidence1", ev1_der)

    # Build Example 2
    ev2_der = build_example2(ak_private_key, ak_cert, int_cert)
    write_b64_and_pem(SAMPLEDATA_DIR / "evidence2", ev2_der)
    write_pretty_print(SAMPLEDATA_DIR / "evidence2", ev2_der)


    # Build Example 3
    ev3_der = build_example3(ak_private_key, ak_cert, int_cert, ca_private_key, ca_cert)
    write_b64_and_pem(SAMPLEDATA_DIR / "evidence3", ev3_der)
    write_pretty_print(SAMPLEDATA_DIR / "evidence3", ev3_der)