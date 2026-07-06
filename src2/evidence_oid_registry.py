
# ---------------------------------------------------------------------------
# Dependency imports with friendly error messages
# ---------------------------------------------------------------------------
try:
    from pyasn1.type import univ
except ImportError:
    sys.exit("pyasn1 is required.  Install with:  pip install pyasn1 pyasn1-modules")

# ---------------------------------------------------------------------------
# OID Registry
# ---------------------------------------------------------------------------
EVIDENCE_KNOWN_OIDS: dict[str, str] = {
    # Element types
    "transaction": "1.3.6.1.5.5.999.0.0",
    "platform": "1.3.6.1.5.5.999.0.1",
    "key": "1.3.6.1.5.5.999.0.2",
    # Transaction claims
    "transaction-nonce": "1.3.6.1.5.5.999.1.0.0",
    "transaction-timestamp": "1.3.6.1.5.5.999.1.0.1",
    "transaction-ak-spki": "1.3.6.1.5.5.999.1.0.2",
    # Platform claims
    "platform-vendor": "1.3.6.1.5.5.999.1.1.0",
    "platform-oemid": "1.3.6.1.5.5.999.1.1.1",
    "platform-hwmodel": "1.3.6.1.5.5.999.1.1.2",
    "platform-hwversion": "1.3.6.1.5.5.999.1.1.3",
    "platform-hwserial": "1.3.6.1.5.5.999.1.1.4",
    "platform-swname": "1.3.6.1.5.5.999.1.1.5",
    "platform-swversion": "1.3.6.1.5.5.999.1.1.6",
    "platform-debugstat": "1.3.6.1.5.5.999.1.1.7",
    "platform-uptime": "1.3.6.1.5.5.999.1.1.8",
    "platform-bootcount": "1.3.6.1.5.5.999.1.1.9",
    "platform-fipsboot": "1.3.6.1.5.5.999.1.1.10",
    "platform-fipsver": "1.3.6.1.5.5.999.1.1.11",
    "platform-fipslevel": "1.3.6.1.5.5.999.1.1.12",
    "platform-fipsmodule": "1.3.6.1.5.5.999.1.1.13",
    # Key claims
    "key-identifier": "1.3.6.1.5.5.999.1.2.0",
    "key-spki": "1.3.6.1.5.5.999.1.2.1",
    "key-extractable": "1.3.6.1.5.5.999.1.2.2",
    "key-sensitive": "1.3.6.1.5.5.999.1.2.3",
    "key-never-extractable": "1.3.6.1.5.5.999.1.2.4",
    "key-local": "1.3.6.1.5.5.999.1.2.5",
    "key-expiry": "1.3.6.1.5.5.999.1.2.6",
    "key-purpose": "1.3.6.1.5.5.999.1.2.7",
    # Key capabilities
    "capability-encrypt": "1.3.6.1.5.5.999.2.0",
    "capability-decrypt": "1.3.6.1.5.5.999.2.1",
    "capability-wrap": "1.3.6.1.5.5.999.2.2",
    "capability-unwrap": "1.3.6.1.5.5.999.2.3",
    "capability-sign": "1.3.6.1.5.5.999.2.4",
    "capability-sign-recover": "1.3.6.1.5.5.999.2.5",
    "capability-verify": "1.3.6.1.5.5.999.2.6",
    "capability-verify-recover": "1.3.6.1.5.5.999.2.7",
    "capability-derive": "1.3.6.1.5.5.999.2.8",
    # Extended Key Usage
    "id-kp-attestationKey": "1.3.6.1.5.5.7.3.999",
}

# Reverse mapping: dotted-string -> human name
OID_NAMES: dict = {v: k for k, v in EVIDENCE_KNOWN_OIDS.items()}

# Claim OID → expected ASN.1 universal tag number
CLAIM_EXPECTED_TAGS: dict[str, int] = {
    EVIDENCE_KNOWN_OIDS.get("transaction-nonce"):      4,  # OCTET STRING    (nonce)
    EVIDENCE_KNOWN_OIDS.get("transaction-timestamp"): 24,  # GeneralizedTime (timestamp)
    EVIDENCE_KNOWN_OIDS.get("transaction-ak-spki"):    4,  # OCTET STRING    (ak-spki)
    EVIDENCE_KNOWN_OIDS.get("platform-vendor"):       12,  # UTF8String      (vendor)
    EVIDENCE_KNOWN_OIDS.get("platform-oemid"):         4,  # OCTET STRING    (oemid)
    EVIDENCE_KNOWN_OIDS.get("platform-hwmodel"):       4,  # OCTET STRING    (hwmodel)
    EVIDENCE_KNOWN_OIDS.get("platform-hwversion"):    12,  # UTF8String      (hwversion)
    EVIDENCE_KNOWN_OIDS.get("platform-hwserial"):     12,  # UTF8String      (hwserial)
    EVIDENCE_KNOWN_OIDS.get("platform-swname"):       12,  # UTF8String      (swname)
    EVIDENCE_KNOWN_OIDS.get("platform-swversion"):    12,  # UTF8String      (swversion)
    EVIDENCE_KNOWN_OIDS.get("platform-debugstat"):     2,  # INTEGER         (debugstat)
    EVIDENCE_KNOWN_OIDS.get("platform-uptime"):        2,  # INTEGER         (uptime)
    EVIDENCE_KNOWN_OIDS.get("platform-bootcount"):     2,  # INTEGER         (bootcount)
    EVIDENCE_KNOWN_OIDS.get("platform-fipsboot"):      1,  # BOOLEAN         (fipsboot)
    EVIDENCE_KNOWN_OIDS.get("platform-fipsver"):      12,  # UTF8String      (fipsver)
    EVIDENCE_KNOWN_OIDS.get("platform-fipslevel") :    2,  # INTEGER         (fipslevel)
    EVIDENCE_KNOWN_OIDS.get("platform-fipsmodule"):   12,  # UTF8String      (fipsmodule)
    EVIDENCE_KNOWN_OIDS.get("key-identifier"):        12,  # UTF8String      (key-identifier)
    EVIDENCE_KNOWN_OIDS.get("key-spki"):               4,  # OCTET STRING    (key-spki)
    EVIDENCE_KNOWN_OIDS.get("key-extractable"):        1,  # BOOLEAN         (key-extractable)
    EVIDENCE_KNOWN_OIDS.get("key-sensitive"):          1,  # BOOLEAN         (key-sensitive)
    EVIDENCE_KNOWN_OIDS.get("key-never-extractable"):  1,  # BOOLEAN         (key-never-extractable)
    EVIDENCE_KNOWN_OIDS.get("key-local"):              1,  # BOOLEAN         (key-local)
    EVIDENCE_KNOWN_OIDS.get("key-expiry"):            24,  # GeneralizedTime (key-expiry)
    EVIDENCE_KNOWN_OIDS.get("key-purpose"):           16,  # SEQUENCE        (key-purpose / KeyPurposes)
}

KNOWN_ELEMENT_OIDS = {
    EVIDENCE_KNOWN_OIDS.get("transaction"),
    EVIDENCE_KNOWN_OIDS.get("platform"),
    EVIDENCE_KNOWN_OIDS.get("key"),
}
KNOWN_CLAIM_OIDS = set(CLAIM_EXPECTED_TAGS.keys())

def oid_name(oid_str: str) -> str:
    return OID_NAMES.get(oid_str, oid_str)

def evidence_make_oid(dotted: str) -> univ.ObjectIdentifier:
    # Convert name to dotted
    dotted = EVIDENCE_KNOWN_OIDS.get(dotted, dotted)
    return univ.ObjectIdentifier(tuple(int(x) for x in dotted.split(".")))
 

 