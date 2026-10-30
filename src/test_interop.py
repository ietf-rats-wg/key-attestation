"""Bidirectional conformance tests; all private keys remain in memory.

Set PKIX_GO_BIN to a built Go CLI, or the suite builds one in its temporary
folder. Tests never regenerate repository sampledata.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, padding
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ

import create_ak
import main as samples
import pkix_evidence as schema
from evidence_oid_registry import EVIDENCE_KNOWN_OIDS as OIDS
from verification import (verify_evidence, validate_structure, spki_bytes, sign_bytes,
                          claim_value)


def element(kind, claims):
    result = schema.ReportedElement()
    result["elementType"] = schema.evidence_make_oid("id-evidence-element-" + kind)
    for claim in claims:
        result["claims"].append(claim)
    return result


def claim(name, value):
    return schema.make_claim("id-evidence-claim-" + name, value)


def find_element(ev, kind):
    return next(el for el in ev["tbs"]["reportedElements"]
                if str(el["elementType"]) == OIDS["id-evidence-element-" + kind])


def find_claim(ev, name):
    return next(c for el in ev["tbs"]["reportedElements"] for c in el["claims"]
                if str(c["claimType"]) == OIDS["id-evidence-claim-" + name])


def set_key_attributes(key, local, extractable, never_extractable):
    """Replace the local, extractable and never-extractable claims of a key element."""
    names = {"key-local": local, "key-extractable": extractable, "key-never-extractable": never_extractable}
    oids = {OIDS["id-evidence-claim-" + name] for name in names}
    kept = [c for c in key["claims"] if str(c["claimType"]) not in oids]
    key["claims"].clear()
    for c in kept:
        key["claims"].append(c)
    for name, value in names.items():
        key["claims"].append(claim(name, value))


def replace_value(c, value):
    c["value"] = encoder.encode(value)


class InteropBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="pkix-tests-")
        cls.base = Path(cls.directory.name)
        cls.go = os.environ.get("PKIX_GO_BIN", str(cls.base / "pkix-evidence"))
        if "PKIX_GO_BIN" not in os.environ:
            env = dict(os.environ, GOCACHE=os.environ.get("GOCACHE", "/tmp/go-build-key-attestation"))
            subprocess.run(["go", "build", "-o", cls.go, "./go-src/cmd/pkix-evidence"],
                           cwd=Path(__file__).resolve().parent.parent, env=env, check=True)
        # Keep intermediate signing key in memory for additional test AKs.
        root_key, cls.root = create_ak.create_root_ca(Path(cls.base, "ca.crt"))
        cls.issuer_key, cls.intermediate = create_ak.create_int_ca(root_key, cls.root, Path(cls.base, "int.crt"))
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.cert = cls.certificate(cls.key)
        (cls.base / "ak.crt").write_bytes(cls.cert.public_bytes(serialization.Encoding.PEM))
        cls.example = samples.build_example2(cls.key, cls.cert, cls.intermediate)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    @classmethod
    def certificate(cls, key, *, subject=None, eku=True, ku=True, critical_eku=False, valid=True):
        now = datetime.now(timezone.utc)
        builder = (x509.CertificateBuilder()
                   .subject_name(subject or create_ak.build_name("test-ak", "pkix-key-attestation", "ietf-rats"))
                   .issuer_name(cls.intermediate.subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=2))
                   .not_valid_after(now + timedelta(days=1) if valid else now - timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
        if ku:
            builder = builder.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        if eku:
            builder = builder.add_extension(x509.ExtendedKeyUsage([schema.id_kp_attest_oid]), critical=critical_eku)
        return builder.sign(cls.issuer_key, hashes.SHA256())

    def go_run(self, command, data=None, *args, success=True):
        path = self.base / "input.der"
        if data is not None:
            path.write_bytes(data)
        proc = subprocess.run([self.go, command] + (["-in", str(path)] if data is not None else []) + list(args),
                              capture_output=True, text=True, timeout=30)
        if success:
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        else:
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc

    def verify_both(self, data, *, success=True, root=True, **kwargs):
        options = {"roots": [self.root]} if root else {"trusted_spkis": [spki_bytes(self.cert.public_key())]}
        options.update(kwargs)
        py = verify_evidence(data, **options)
        self.assertEqual(py.accepted, success, repr(py))
        args = ["-ca", str(self.base / "ca.crt")] if root else ["-signer-cert", str(self.base / "ak.crt")]
        self.go_run("verify", data, *args, success=success)
        return py

    def resign(self, ev, key=None):
        algorithm, signature = sign_bytes(key or self.key, encoder.encode(ev["tbs"]))
        ev["signatures"][0]["signatureValue"] = signature
        return schema.encode_evidence(ev)

    def two_signers(self, second_key=None, second_cert=None):
        second_key = second_key or ed25519.Ed25519PrivateKey.generate()
        second_cert = second_cert or self.certificate(second_key)
        evidence = schema.PkixEvidence()
        evidence.add_element(element("platform", [claim("platform-vendor", "Acme Corp")]))
        evidence.sign_and_encode(self.cert, self.key, self.intermediate)
        return evidence.sign_and_encode(second_cert, second_key, self.intermediate)


class PositiveInteropTests(InteropBase):
    def test_python_embedded_certificate_to_go(self):
        self.verify_both(self.example)
        doc = json.loads(self.go_run("decode", self.example).stdout)
        self.assertEqual([el["typeName"] for el in doc["elements"]], ["transaction", "platform", "key", "key"])
        for el in doc["elements"]:
            for c in el["claims"]:
                self.assertNotEqual(c["valueKind"], "unknown")
                self.assertTrue(c["typeName"])
        purpose = next(c for el in doc["elements"] for c in el["claims"] if c["typeName"] == "purpose")
        self.assertEqual(purpose["valueKind"], "purposes")
        self.assertEqual(purpose["value"], ["sign"])
        false_values = [c["value"] for el in doc["elements"] for c in el["claims"] if c["valueKind"] == "bool" and c["value"] is False]
        self.assertTrue(false_values)

    def test_python_key_id_out_of_band_to_go(self):
        data = samples.build_example1(self.key, self.cert, self.intermediate)
        result = verify_evidence(data, roots=[self.root], key_resolver=lambda identifier: self.cert
                                 if identifier == self.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest else None)
        self.assertTrue(result.accepted, repr(result))
        self.go_run("verify", data, "-ca", str(self.base / "ca.crt"), "-signer-cert", str(self.base / "ak.crt"))

    def test_go_to_python_with_path_and_nonce(self):
        output = self.base / "go.der"
        self.go_run("generate", None, "-out", str(output), "-nonce-hex", "deadbeef")
        data = output.read_bytes()
        ev = schema.decode_evidence(data)
        from verification import resolve_signer
        _, cert = resolve_signer(ev["signatures"][0]["sid"], [], None)
        result = verify_evidence(data, roots=[cert], expected_nonce=bytes.fromhex("deadbeef"))
        self.assertTrue(result.accepted, repr(result))
        self.assertEqual(bytes(claim_value(find_claim(ev, "transaction-nonce"))), bytes.fromhex("deadbeef"))
        purposes = [str(oid) for oid in claim_value(find_claim(ev, "key-purpose"))]
        self.assertEqual(purposes, [OIDS["id-evidence-key-capability-sign"], OIDS["id-evidence-key-capability-decapsulate"]])
        pem = self.base / "go.crt"
        pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.go_run("verify", data, "-ca", str(pem), "-nonce-hex", "deadbeef")

    def test_independently_assembled_der_envelope(self):
        # Assemble the whole ASN.1 envelope without either implementation's schema.
        def tlv(tag, content):
            n = len(content)
            size = bytes([n]) if n < 128 else bytes([0x80 + (n.bit_length() + 7) // 8]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
            return bytes([tag]) + size + content
        seq = lambda content: tlv(0x30, content)
        key = ed25519.Ed25519PrivateKey.generate()
        public = spki_bytes(key.public_key())
        vendor = bytes.fromhex("3017060a2b0601050587670101000c0941636d6520436f7270")
        platform_oid = bytes.fromhex("06092b0601050587670001")
        tbs = seq(bytes.fromhex("020101") + seq(seq(platform_oid + seq(vendor))))
        sid = seq(tlv(0xa1, public))
        algorithm = seq(bytes.fromhex("06032b6570"))
        block = seq(sid + algorithm + tlv(4, key.sign(tbs)))
        data = seq(tbs + seq(block))
        result = verify_evidence(data, trusted_spkis=[public])
        self.assertTrue(result.accepted, repr(result))
        pin = self.base / "independent.crt"
        pin.write_bytes(self.certificate(key).public_bytes(serialization.Encoding.PEM))
        self.go_run("verify", data, "-signer-cert", str(pin))
        doc = json.loads(self.go_run("decode", data).stdout)
        self.assertEqual(doc["elements"][0]["claims"][0]["value"], "Acme Corp")

    def test_literal_asn1_claim_reference(self):
        # Independently transcribed DER: SEQUENCE { vendor OID, UTF8String "Acme Corp" }.
        literal = bytes.fromhex("3017060a2b0601050587670101000c0941636d6520436f7270")
        self.assertEqual(encoder.encode(claim("platform-vendor", "Acme Corp")), literal)
        ev = schema.decode_evidence(self.example)
        find_element(ev, "platform")["claims"].append(decoder.decode(literal, asn1Spec=schema.ReportedClaim())[0])
        data = self.resign(ev)
        self.verify_both(data)
        doc = json.loads(self.go_run("decode", data).stdout)
        vendor = next(c for el in doc["elements"] for c in el["claims"] if c["typeName"] == "vendor")
        self.assertEqual(vendor["value"], "Acme Corp")

    def test_critical_attestation_eku(self):
        cert = self.certificate(self.key, critical_eku=True)
        self.verify_both(samples.build_example2(self.key, cert, self.intermediate))

    def test_rsa_and_ed25519(self):
        for key in [rsa.generate_private_key(65537, 2048), ed25519.Ed25519PrivateKey.generate()]:
            with self.subTest(key=type(key).__name__):
                cert = self.certificate(key)
                self.verify_both(samples.build_example2(key, cert, self.intermediate))

    def test_rsa_pss_sha256(self):
        key = rsa.generate_private_key(65537, 2048)
        cert = self.certificate(key)
        ev = schema.decode_evidence(samples.build_example2(key, cert, self.intermediate))
        # Independently transcribed SHA-256 / MGF1-SHA-256 / 32-byte salt parameters.
        params = bytes.fromhex("3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120")
        block = ev["signatures"][0]
        block["signatureAlgorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.840.113549.1.1.10")
        block["signatureAlgorithm"]["parameters"] = params
        block["signatureValue"] = key.sign(encoder.encode(ev["tbs"]), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        self.verify_both(schema.encode_evidence(ev))

    def test_generalized_time_fraction_and_large_integer(self):
        ev = schema.decode_evidence(self.example)
        from pyasn1.type import useful
        replace_value(find_claim(ev, "transaction-timestamp"), useful.GeneralizedTime("20261019120000.123Z"))
        find_element(ev, "platform")["claims"].append(claim("platform-uptime", 2 ** 100))
        self.verify_both(self.resign(ev))

    def test_multiple_signers_and_verified_ak_claims(self):
        result = self.verify_both(self.two_signers())
        self.assertEqual(len(result.verified_ak_spkis), 2)

    def test_unknown_key_algorithm_preserves_algorithm_agility(self):
        ev = schema.decode_evidence(self.two_signers())
        sid = ev["signatures"][1]["sid"]
        certificate = schema.tagged_component_value(schema.Certificate(), sid["certificate"])
        public = certificate["tbsCertificate"]["subjectPublicKeyInfo"]
        public["algorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.3.4.99")
        public["subjectPublicKey"] = univ.BitString.fromOctetString(b"future-key-format")
        # Keep the certificate's issuer signature valid; only the AK algorithm is unknown.
        certificate["signature"] = univ.BitString.fromOctetString(self.issuer_key.sign(encoder.encode(certificate["tbsCertificate"]), ec.ECDSA(hashes.SHA256())))
        sid["certificate"] = schema.tagged_component_value(sid["certificate"], certificate)
        claims = find_element(ev, "transaction")["claims"]
        ak_claims = [c for c in claims if str(c["claimType"]) == OIDS["id-evidence-claim-transaction-ak-spki"]]
        replace_value(ak_claims[1], public)
        ev["signatures"][1]["signatureAlgorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.3.4.100")
        result = self.verify_both(self.resign(ev))
        self.assertEqual(len(result.verified_ak_spkis), 1)

    def test_unknown_algorithm_does_not_invalidate_valid_signature(self):
        ev = schema.decode_evidence(self.two_signers())
        ev["signatures"][1]["signatureAlgorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.3.4.5")
        data = schema.encode_evidence(ev)
        result = self.verify_both(data)
        self.assertEqual(len(result.verified_ak_spkis), 1)
        self.assertIsNone(result.signatures[0])
        self.assertIsNotNone(result.signatures[1])
        self.assertFalse(verify_evidence(data, roots=[self.root], require_all=True).accepted)
        self.go_run("verify", data, "-ca", str(self.base / "ca.crt"), "-require-all", success=False)

    def test_algorithm_allowlist(self):
        data = self.two_signers()
        result = verify_evidence(data, roots=[self.root], allowed_algorithms={"1.2.840.10045.4.3.2"})
        self.assertTrue(result.accepted, repr(result))
        self.assertEqual(len(result.verified_ak_spkis), 1)
        self.go_run("verify", data, "-ca", str(self.base / "ca.crt"), "-algorithms", "1.2.840.10045.4.3.2")
        self.assertFalse(verify_evidence(data, roots=[self.root], allowed_algorithms=set()).accepted)
        self.go_run("verify", data, "-ca", str(self.base / "ca.crt"), "-algorithms", "1.2.3", success=False)

    def test_additional_bad_certificate_block_is_independent(self):
        key = ed25519.Ed25519PrivateKey.generate()
        data = self.two_signers(key, self.certificate(key, eku=False))
        self.verify_both(data)

    def test_raw_spki_pinned(self):
        ev = schema.decode_evidence(self.example)
        sid = schema.SignerIdentifier()
        spki = decoder.decode(spki_bytes(self.key.public_key()), asn1Spec=schema.SubjectPublicKeyInfo())[0]
        sid["subjectPublicKeyInfo"] = schema.tagged_component_value(sid["subjectPublicKeyInfo"], spki)
        ev["signatures"][0]["sid"] = sid
        self.verify_both(schema.encode_evidence(ev), root=False)

    def test_unknown_extensions_are_skipped(self):
        ev = schema.decode_evidence(self.example)
        custom = schema.ReportedClaim()
        custom["claimType"] = univ.ObjectIdentifier("1.2.3.4.5")
        custom["value"] = encoder.encode(univ.SequenceOf(componentType=univ.Boolean()).setComponentByPosition(0, True))
        find_element(ev, "platform")["claims"].append(custom)
        unknown = schema.ReportedElement()
        unknown["elementType"] = univ.ObjectIdentifier("1.2.3.4.6")
        unknown["claims"].append(custom)
        ev["tbs"]["reportedElements"].append(unknown)
        data = self.resign(ev)
        self.verify_both(data)
        self.go_run("decode", data)

    def test_identifier_alias_within_same_element(self):
        ev = schema.decode_evidence(self.example)
        key = find_element(ev, "key")
        key["claims"].append(key["claims"][0])
        self.verify_both(self.resign(ev))

    def test_common_criteria_claims(self):
        for scheme, eal in [("ISO15408:2022", "EAL4+AVA_VAN.5,ALC_FLR.3"), ("CCRA v3.1r5", "EAL1"),
                            ("ProprietaryScheme", "free-form level")]:
            with self.subTest(scheme=scheme, eal=eal):
                ev = schema.decode_evidence(self.example)
                platform = find_element(ev, "platform")
                platform["claims"].append(claim("platform-ccmoduleid", "Example HSM"))
                platform["claims"].append(claim("platform-ccboot", True))
                platform["claims"].append(claim("platform-ccscheme", scheme))
                platform["claims"].append(claim("platform-ccrequirement", "EN 419 221-5:2018"))
                platform["claims"].append(claim("platform-cceallevel", eal))
                data = self.resign(ev)
                self.verify_both(data)
                self.go_run("validate", data)

    def test_device_bound_key(self):
        ev = schema.decode_evidence(self.example)
        set_key_attributes(find_element(ev, "key"), local=True, extractable=False, never_extractable=True)
        find_element(ev, "key")["claims"].append(claim("key-device-bound", True))
        data = self.resign(ev)
        self.verify_both(data)
        self.go_run("validate", data)

    def test_verifier_allows_absent_optional_ak_claim(self):
        ev = schema.decode_evidence(self.example)
        tx = find_element(ev, "transaction")
        kept = [c for c in tx["claims"] if str(c["claimType"]) != OIDS["id-evidence-claim-transaction-ak-spki"]]
        tx["claims"].clear()
        for c in kept:
            tx["claims"].append(c)
        self.verify_both(self.resign(ev))

    def test_all_text_formats(self):
        for suffix, data in [("der", self.example), ("b64", base64.b64encode(self.example)),
                             ("spaced-b64", b" \n" + b" \t".join([base64.b64encode(self.example)[:40], base64.b64encode(self.example)[40:]]) + b"\n"),
                             ("pem", b"-----BEGIN EVIDENCE-----\n" + base64.b64encode(self.example) + b"\n-----END EVIDENCE-----\n")]:
            with self.subTest(format=suffix):
                self.go_run("validate", data)
                path = self.base / ("format." + suffix)
                path.write_bytes(data)
                self.assertEqual(encoder.encode(samples.read_evidence_file(path)), self.example)


class NegativeInteropTests(InteropBase):
    def test_invalid_structure_with_valid_signature(self):
        def bad_version(ev): ev["tbs"]["version"] = 2
        def repeated_platform(ev): ev["tbs"]["reportedElements"].append(find_element(ev, "platform"))
        def repeated_transaction(ev): ev["tbs"]["reportedElements"].append(find_element(ev, "transaction"))
        def repeated_nonce(ev): find_element(ev, "transaction")["claims"].append(find_claim(ev, "transaction-nonce"))
        def wrong_owner(ev): find_element(ev, "platform")["claims"].append(claim("transaction-nonce", b"bad"))
        def wrong_identifier(ev): replace_value(find_claim(ev, "key-identifier"), univ.OctetString(b"wrong"))
        def bad_spki(ev): replace_value(find_claim(ev, "key-spki"), univ.OctetString(b"bad"))
        def duplicate_key(ev): ev["tbs"]["reportedElements"].append(find_element(ev, "key"))
        def duplicate_ak(ev): find_element(ev, "transaction")["claims"].append(find_claim(ev, "transaction-ak-spki"))
        def bad_level(ev): find_element(ev, "platform")["claims"].append(claim("platform-fipslevel", 5))
        def extractable_device_bound(ev):
            key = find_element(ev, "key")
            set_key_attributes(key, local=True, extractable=True, never_extractable=True)
            key["claims"].append(claim("key-device-bound", True))
        def bad_eal(ev):
            platform = find_element(ev, "platform")
            platform["claims"].append(claim("platform-ccscheme", "EUCC"))
            platform["claims"].append(claim("platform-cceallevel", "EAL8+AVA_VAN.5"))
        def old_tag(ev): find_claim(ev, "key-identifier")["value"] = b"\x81\x03old"
        def wrong_purpose(ev): replace_value(find_claim(ev, "key-purpose"), univ.OctetString(b"\x30\x00"))
        def missing_identifier(ev):
            key = find_element(ev, "key")
            kept = [c for c in key["claims"] if str(c["claimType"]) != OIDS["id-evidence-claim-key-identifier"]]
            key["claims"].clear()
            for c in kept: key["claims"].append(c)
        for mutate in [bad_version, repeated_platform, repeated_transaction, repeated_nonce, wrong_owner,
                       wrong_identifier, bad_spki, duplicate_key, duplicate_ak, bad_level, bad_eal, extractable_device_bound, old_tag, wrong_purpose, missing_identifier]:
            with self.subTest(case=mutate.__name__):
                ev = schema.decode_evidence(self.example)
                mutate(ev)
                data = self.resign(ev)
                self.verify_both(data, success=False)
                self.go_run("validate", data, success=False)

    def test_empty_evidence_and_missing_value(self):
        # Empty TBS elements and signatures, independently constructed DER.
        for data in [bytes.fromhex("3009300502010130003000"), self.example + b"\x00"]:
            with self.subTest(data=data[:20].hex()):
                self.verify_both(data, success=False)
                self.go_run("validate", data, success=False)
        ev = schema.decode_evidence(self.example)
        find_claim(ev, "key-identifier")["value"] = b"\x05\x00"
        self.verify_both(self.resign(ev), success=False)
        with self.assertRaises(Exception): schema.decode_evidence(bytes.fromhex("3009300502010130003000"))

    def test_each_required_sequence_nonempty(self):
        for target in ("signatures", "elements", "claims"):
            with self.subTest(target=target):
                generic = decoder.decode(self.example)[0]
                if target == "signatures": generic[1].clear()
                elif target == "elements": generic[0][1].clear()
                else: generic[0][1][0][1].clear()
                data = encoder.encode(generic)
                self.verify_both(data, success=False)
                self.go_run("validate", data, success=False)

    def test_noncanonical_time_and_integer(self):
        for value in (b"20261019120000+0000", b"20261019120000.120Z", b"20261019120000"):
            with self.subTest(time=value):
                ev = schema.decode_evidence(self.example)
                find_claim(ev, "transaction-timestamp")["value"] = bytes([24, len(value)]) + value
                self.verify_both(self.resign(ev), success=False)
        ev = schema.decode_evidence(self.example)
        find_element(ev, "platform")["claims"].append(claim("platform-uptime", 1))
        find_claim(ev, "platform-uptime")["value"] = b"\x02\x02\x00\x01"
        self.verify_both(self.resign(ev), success=False)

    def test_rsa_pss_mismatched_mgf(self):
        key = rsa.generate_private_key(65537, 2048)
        cert = self.certificate(key)
        ev = schema.decode_evidence(samples.build_example2(key, cert, self.intermediate))
        params = bytes.fromhex("3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020120")
        block = ev["signatures"][0]
        block["signatureAlgorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.840.113549.1.1.10")
        block["signatureAlgorithm"]["parameters"] = params
        # Valid RSA-PSS signature for the advertised SHA-384 MGF, intentionally unsupported.
        block["signatureValue"] = key.sign(encoder.encode(ev["tbs"]), padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=32), hashes.SHA256())
        self.verify_both(schema.encode_evidence(ev), success=False)

    def test_empty_sid(self):
        ev = schema.decode_evidence(self.example)
        ev["signatures"][0]["sid"] = schema.SignerIdentifier()
        self.verify_both(schema.encode_evidence(ev), success=False)

    def test_corrupted_signature(self):
        ev = schema.decode_evidence(self.example)
        value = bytearray(ev["signatures"][0]["signatureValue"])
        value[-1] ^= 1
        ev["signatures"][0]["signatureValue"] = bytes(value)
        self.verify_both(schema.encode_evidence(ev), success=False)

    def test_unresolved_key_id_rejects_even_with_valid_block(self):
        ev = schema.decode_evidence(self.two_signers())
        sid = schema.SignerIdentifier()
        sid["keyId"] = b"unresolvable"
        ev["signatures"][1]["sid"] = sid
        self.verify_both(schema.encode_evidence(ev), success=False)

    def test_conflicting_sid(self):
        ev = schema.decode_evidence(self.example)
        other = ec.generate_private_key(ec.SECP256R1())
        spki = decoder.decode(spki_bytes(other.public_key()), asn1Spec=schema.SubjectPublicKeyInfo())[0]
        sid = ev["signatures"][0]["sid"]
        sid["subjectPublicKeyInfo"] = schema.tagged_component_value(sid["subjectPublicKeyInfo"], spki)
        self.verify_both(schema.encode_evidence(ev), success=False)

    def test_identity_mismatch(self):
        other = ed25519.Ed25519PrivateKey.generate()
        cert = self.certificate(other, subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "other-attester")]))
        self.verify_both(self.two_signers(other, cert), success=False)

    def test_duplicate_certificate_spki(self):
        ev = schema.decode_evidence(self.example)
        ev["signatures"].append(ev["signatures"][0])
        self.verify_both(schema.encode_evidence(ev), success=False)

    def test_missing_ku_eku_and_expired_cert(self):
        for kwargs in [{"ku": False}, {"eku": False}, {"valid": False}]:
            with self.subTest(case=kwargs):
                cert = self.certificate(self.key, **kwargs)
                self.verify_both(samples.build_example2(self.key, cert, self.intermediate), success=False)

    def test_binding_mismatch(self):
        ev = schema.decode_evidence(self.example)
        other = ec.generate_private_key(ec.SECP256R1())
        find_claim(ev, "transaction-ak-spki")["value"] = spki_bytes(other.public_key())
        self.verify_both(self.resign(ev), success=False)

    def test_missing_trust_and_wrong_nonce(self):
        self.assertFalse(verify_evidence(self.example).accepted)
        self.go_run("verify", self.example, success=False)
        self.assertFalse(verify_evidence(self.example, roots=[self.root], expected_nonce=b"wrong").accepted)
        self.go_run("verify", self.example, "-ca", str(self.base / "ca.crt"), "-nonce-hex", "0011", success=False)

    def test_invalid_algorithm_parameters(self):
        ev = schema.decode_evidence(self.example)
        ev["signatures"][0]["signatureAlgorithm"]["parameters"] = b"\x05\x00"
        self.verify_both(schema.encode_evidence(ev), success=False)

    def test_noncanonical_claim_boolean(self):
        ev = schema.decode_evidence(self.example)
        find_claim(ev, "key-sensitive")["value"] = b"\x01\x01\x01"
        self.verify_both(self.resign(ev), success=False)

    def test_unknown_claim_without_value(self):
        # A generic sequence permits omitting a mandatory field for this negative vector.
        ev = decoder.decode(self.example)[0]
        custom = univ.Sequence()
        custom[0] = univ.ObjectIdentifier("1.2.3.4.5")
        ev[0][1][1][1].append(custom)
        data = encoder.encode(ev)
        self.verify_both(data, success=False)
        self.go_run("validate", data, success=False)

    def test_reject_implicit_certificates(self):
        ev = schema.decode_evidence(self.example)
        data = schema.encode_evidence(ev)
        # Strip the inner SEQUENCE, preserving the [0] wrapper as an implicit list.
        from pyasn1.type.tag import Tag, tagClassContext, tagFormatConstructed
        implicit = schema.CertificateSeq().subtype(implicitTag=Tag(tagClassContext, tagFormatConstructed, 0))
        for c in ev["intermediateCertificates"]: implicit.append(c)
        outer = decoder.decode(data)[0]
        outer.setComponentByPosition(2, implicit)
        self.verify_both(encoder.encode(outer), success=False)


if __name__ == "__main__":
    unittest.main()
