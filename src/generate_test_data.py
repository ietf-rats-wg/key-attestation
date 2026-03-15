from pkix_evidence import *

evidence_file = SAMPLEDATA_DIR / "evidence.b64"


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
        if sid["subjectPublicKeyInfo"].hasValue():
            spki_alg = _fmt_oid(
                sid["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
            )
            print(f"{pad}      SPKI algorithm : {spki_alg}")
        if sid["certificate"].hasValue():
            print(f"{pad}      certificate    : <present, rfc5280.Certificate>")



# ---------------------------------------------------------------------------
# Main — end-to-end DER round-trip demonstration
# ---------------------------------------------------------------------------

def build_example1(ak_private_key: ec.EllipticCurvePrivateKey, ak_cert: x509.Certificate, int_cert: x509.Certificate) -> bytes:
    """Build a sample Evidence object for testing."""
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
    plat_claims[1] = make_claim("id-evidence-claim-platform-hwmodel",   b"HSM-9000")
    plat_claims[2] = make_claim("id-evidence-claim-platform-hwversion", "2.1.0")
    plat_claims[3] = make_claim("id-evidence-claim-platform-fipsboot",  True)
    plat_claims[4] = make_claim("id-evidence-claim-platform-fipslevel", 3)
    plat_claims[5] = make_claim("id-evidence-claim-platform-uptime",    86400)

    plat_entity = ReportedEntity()
    plat_entity["entityType"] = mkoid("id-evidence-entity-platform")
    plat_entity["claims"]     = plat_claims

    ev.add_entity(plat_entity)


    # Key entity
    key_claims = ReportedClaimSeq()
    key_claims[0] = make_claim(
        "id-evidence-claim-key-identifier",
        "key-001",
    )
    key_claims[1] = make_claim("id-evidence-claim-key-extractable",       False)
    key_claims[2] = make_claim("id-evidence-claim-key-never-extractable", True)
    key_claims[3] = make_claim("id-evidence-claim-key-sensitive",         True)
    key_claims[4] = make_claim("id-evidence-claim-key-local",             True)
    key_claims[5] = make_claim(
        "id-evidence-claim-key-purpose",
        encode_key_capabilities(build_example_key_capabilities()),
    )

    key_entity = ReportedEntity()
    key_entity["entityType"] = mkoid("id-evidence-entity-key")
    key_entity["claims"]     = key_claims

    ev.add_entity(key_entity)


    return ev.sign_and_encode(ak_cert, ak_private_key, int_cert)


if __name__ == "__main__":
    # generate AK key and cert chain
    ak_private_key, ak_cert, int_cert, _ca_cert = create_ak.generateAndSaveCerts()



    ev_der = build_example1(ak_private_key, ak_cert, int_cert)

    with evidence_file.open("w") as f:
        f.write(base64.b64encode(ev_der).decode("ascii"))



#     SEP = "=" * 62
#
#     print(SEP)
#     print("  PKIX-Evidence-2025  |  DER round-trip  (pyasn1_alt_modules)")
#     print(SEP)
#
#     # Evidence round-trip
#     print("\n[1] Building Evidence ...")
#     ev = build_example_evidence()
#
#     print("[2] DER encoding ...")
#     der = encode_evidence(ev)
#     print(f"    {len(der)} bytes encoded")
#     print(f"    Bytes: {der.hex()}")
#
#     evidence_file = SAMPLEDATA_DIR / "evidence.b64"
#     print("[2a] Saving evidence to "+evidence_file.as_posix())
#
#     evidence_file.parent.mkdir(parents=True, exist_ok=True)
#     with evidence_file.open("w") as f:
#         f.write(base64.b64encode(der).decode("ascii"))
#
#     print("\n[3] DER decoding ...")
#     ev2 = decode_evidence(der)
#
#     print("\n[4] Decoded structure:")
#     pretty_print_evidence(ev2, indent=1)
#
#     print("\n[5] Re-encoding decoded object (round-trip check) ...")
#     der2 = encode_evidence(ev2)
#     assert der == der2, "ROUND-TRIP MISMATCH -- encoded bytes differ!"
#     print("    OK  Bytes are identical -- round-trip passed")
#
#     # EvidenceKeyCapabilities round-trip
#     print(f"\n{SEP}")
#     print("[6] Building EvidenceKeyCapabilities ...")
#     caps = build_example_key_capabilities()
#     der_caps = encode_key_capabilities(caps)
#     print(f"    {len(der_caps)} bytes encoded")
#
#     caps2 = decode_key_capabilities(der_caps)
#     print("    Decoded capabilities:")
#     for cap in caps2:
#         print(f"      {_fmt_oid(cap)}")
#
#     der_caps2 = encode_key_capabilities(caps2)
#     assert der_caps == der_caps2, "ROUND-TRIP MISMATCH -- key capabilities differ!"
#     print("    OK  Round-trip passed")
#
#     # Confirm rfc5280 type provenance
#     print(f"\n{SEP}")
#     print("[7] Confirming rfc5280 type provenance ...")
#     from pyasn1_alt_modules import rfc5280
#     sig = ev2["signatures"][0]
#     alg = sig["signatureAlgorithm"]
#     assert type(alg) is rfc5280.AlgorithmIdentifier, (
#         f"Expected rfc5280.AlgorithmIdentifier, got {type(alg)}"
#     )
#     print(f"    signatureAlgorithm type : {type(alg).__module__}.{type(alg).__qualname__}")
#     print(f"    algorithm OID           : {_fmt_oid(alg['algorithm'])}")
#     sid_decoded = ev2["signatures"][0]["sid"]
#     print(f"    SignerIdentifier.keyId  : {bytes(sid_decoded['keyId']).hex()}")
#     print("    OK  All rfc5280 types verified")
