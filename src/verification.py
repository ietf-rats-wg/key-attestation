"""Draft structural validation and policy-based signature verification.

Certificate paths use the system OpenSSL 3 executable with purpose 'any'; the
attestation KU/EKU is checked separately, including a critical custom EKU.
No private keys are written to disk. An explicit signature_only mode performs
cryptographic checks without establishing signer trust.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, padding
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, char, useful
from evidence_oid_registry import EVIDENCE_KNOWN_OIDS as OIDS, CLAIM_EXPECTED_TAGS
import re

# Common Criteria schemes whose cceallevel claim must follow the EAL syntax.
CC_EAL_SCHEMES = ("ISO15408", "CCRA", "EUCC")
# Key claim values implied by device-bound = TRUE.
DEVICE_BOUND_IMPLIES = {
    OIDS["id-evidence-claim-key-local"]: True,
    OIDS["id-evidence-claim-key-extractable"]: False,
    OIDS["id-evidence-claim-key-never-extractable"]: True,
}
CC_EAL_PATTERN = re.compile(r"EAL[1-7](\+[A-Z]{3}_[A-Z]{3}\.[0-9]+(,[A-Z]{3}_[A-Z]{3}\.[0-9]+)*)?")


def spki_bytes(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _exact(data, schema):
    value, rest = decoder.decode(data, asn1Spec=schema)
    if rest or encoder.encode(value) != data:
        raise ValueError("Noncanonical DER or trailing data")
    return value


def claim_value(claim):
    raw = encoder.encode(claim["value"])
    expected = CLAIM_EXPECTED_TAGS.get(str(claim["claimType"]))
    schemas = {1: univ.Boolean, 2: univ.Integer, 4: univ.OctetString,
               12: char.UTF8String, 24: useful.GeneralizedTime,
               16: lambda: univ.SequenceOf(componentType=univ.ObjectIdentifier())}
    if expected is None:
        return raw
    value = _exact(raw, schemas[expected]())
    if expected == 24:
        from generalized_time_validator import validate_generalized_time
        result = validate_generalized_time(str(value), require_utc=True)
        if not result:
            raise ValueError(result.error)
    return value


def validate_structure(ev):
    """Raise ValueError for malformed envelopes or known claim values."""
    if int(ev["tbs"]["version"]) != 1:
        raise ValueError("tbs.version must be 1")
    if not len(ev["signatures"]) or not len(ev["tbs"]["reportedElements"]):
        raise ValueError("Evidence requires signatures and elements")
    for block in ev["signatures"]:
        if not any(block["sid"][name].hasValue() for name in ("keyId", "certificate", "subjectPublicKeyInfo")):
            raise ValueError("Empty SignerIdentifier")
    seen_elements, key_ids, ak_keys = set(), {}, set()
    for index, element in enumerate(ev["tbs"]["reportedElements"]):
        element_oid = str(element["elementType"])
        if element_oid in (OIDS["id-evidence-element-platform"], OIDS["id-evidence-element-transaction"]):
            if element_oid in seen_elements:
                raise ValueError("Repeated platform or transaction element")
            seen_elements.add(element_oid)
        if not len(element["claims"]):
            raise ValueError("Element requires claims")
        counts, identifiers, values = {}, [], {}
        for claim in element["claims"]:
            oid = str(claim["claimType"])
            if not claim["value"].hasValue() or not encoder.encode(claim["value"]):
                raise ValueError("Claim requires a value")
            if oid not in CLAIM_EXPECTED_TAGS:
                continue
            # All standard claim OIDs share the suffix structure <root>.1.<element>.<claim>.
            owner = oid.rsplit(".", 1)[0].replace(".999.1.", ".999.0.")
            if owner != element_oid:
                raise ValueError("Claim belongs to a different element type")
            counts[oid] = counts.get(oid, 0) + 1
            if counts[oid] > 1 and oid not in (OIDS["id-evidence-claim-key-identifier"], OIDS["id-evidence-claim-transaction-ak-spki"]):
                raise ValueError("Claim must not be repeated")
            value = claim_value(claim)
            if oid in (OIDS["id-evidence-claim-key-spki"], OIDS["id-evidence-claim-transaction-ak-spki"]):
                from pkix_evidence import SubjectPublicKeyInfo
                _exact(bytes(value), SubjectPublicKeyInfo())
                try:
                    serialization.load_der_public_key(bytes(value))
                except UnsupportedAlgorithm:
                    pass
            if oid == OIDS["id-evidence-claim-platform-fipslevel"] and int(value) not in range(1, 5):
                raise ValueError("fipslevel must be in range 1..4")
            if oid == OIDS["id-evidence-claim-key-identifier"]:
                identifiers.append(str(value))
            values[oid] = value
            if oid == OIDS["id-evidence-claim-transaction-ak-spki"]:
                key_bytes = bytes(value)
                try:
                    key_bytes = spki_bytes(serialization.load_der_public_key(key_bytes))
                except Exception:
                    pass  # An unsupported key algorithm is still valid SPKI syntax.
                if key_bytes in ak_keys:
                    raise ValueError("Repeated attestation key")
                ak_keys.add(key_bytes)
        scheme = values.get(OIDS["id-evidence-claim-platform-ccscheme"])
        eal = values.get(OIDS["id-evidence-claim-platform-cceallevel"])
        if scheme is not None and eal is not None and str(scheme).startswith(CC_EAL_SCHEMES):
            if not CC_EAL_PATTERN.fullmatch(str(eal)):
                raise ValueError("cceallevel must follow the EAL syntax")
        if element_oid == OIDS["id-evidence-element-key"]:
            device_bound = values.get(OIDS["id-evidence-claim-key-device-bound"])
            if device_bound is not None and bool(device_bound):
                for implied_oid, expected in DEVICE_BOUND_IMPLIES.items():
                    if implied_oid in values and bool(values[implied_oid]) != expected:
                        raise ValueError("device-bound contradicts local, extractable or never-extractable")
            if not identifiers:
                raise ValueError("Key element requires identifier")
            for identifier in identifiers:
                if identifier in key_ids and key_ids[identifier] != index:
                    raise ValueError("Duplicate addressable key")
                key_ids[identifier] = index
    return ak_keys


def check_certificate(cert):
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Signer must be an end-entity certificate")
    except x509.ExtensionNotFound:
        pass
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if not ku.digital_signature:
        raise ValueError("Certificate requires digitalSignature KeyUsage")
    if x509.ObjectIdentifier(OIDS["id-kp-attestationKey"]) not in eku:
        raise ValueError("Certificate requires attestation EKU")


def verify_path(cert, intermediates, roots, current_time=None):
    if not roots:
        raise ValueError("Trust roots are required")
    with tempfile.TemporaryDirectory(prefix="pkix-path-") as directory:
        base = Path(directory)
        pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
        (base / "leaf.pem").write_bytes(pem(cert))
        (base / "roots.pem").write_bytes(b"".join(pem(c) for c in roots))
        args = ["openssl", "verify", "-purpose", "any", "-CAfile", str(base / "roots.pem"),
                "-no-CApath", "-no-CAstore"]
        if intermediates:
            (base / "intermediates.pem").write_bytes(b"".join(pem(c) for c in intermediates))
            args += ["-untrusted", str(base / "intermediates.pem")]
        if current_time is not None:
            args += ["-attime", str(int(current_time.timestamp()))]
        result = subprocess.run(args + [str(base / "leaf.pem")], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise ValueError("Certificate path failed: " + result.stderr.strip())


class UnresolvedKeyID(ValueError):
    pass


class InconsistentSID(ValueError):
    pass


def resolve_signer(sid, intermediates, resolver):
    from pkix_evidence import tagged_component_value, Certificate, SubjectPublicKeyInfo
    cert, keys = None, []
    if sid["certificate"].hasValue():
        raw = encoder.encode(tagged_component_value(Certificate(), sid["certificate"]))
        cert = x509.load_der_x509_certificate(raw)
        keys.append(cert.public_key())
    if sid["subjectPublicKeyInfo"].hasValue():
        raw = encoder.encode(tagged_component_value(SubjectPublicKeyInfo(), sid["subjectPublicKeyInfo"]))
        keys.append(serialization.load_der_public_key(raw))
    if sid["keyId"].hasValue():
        identifier = bytes(sid["keyId"])
        if resolver is not None:
            try:
                resolved = resolver(identifier)
            except Exception as exc:
                raise UnresolvedKeyID("Unable to resolve keyId") from exc
            if resolved is None:
                raise UnresolvedKeyID("Unable to resolve keyId")
            candidates = [resolved]
        else:
            candidates = []
            for candidate in intermediates + ([cert] if cert else []):
                try:
                    if candidate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest == identifier:
                        candidates.append(candidate)
                except x509.ExtensionNotFound:
                    pass
            if not candidates:
                raise UnresolvedKeyID("Unable to resolve keyId")
        for candidate in candidates:
            if isinstance(candidate, x509.Certificate):
                keys.append(candidate.public_key())
                if cert is None:
                    cert = candidate
            else:
                keys.append(candidate)
    if not keys:
        raise ValueError("No signer public key")
    if len({spki_bytes(key) for key in keys}) != 1:
        raise InconsistentSID("Conflicting SignerIdentifier keys")
    return keys[0], cert


_HASHES = {"1.2.840.10045.4.3.2": hashes.SHA256, "1.2.840.10045.4.3.3": hashes.SHA384,
           "1.2.840.10045.4.3.4": hashes.SHA512, "1.2.840.113549.1.1.5": hashes.SHA1,
           "1.2.840.113549.1.1.11": hashes.SHA256, "1.2.840.113549.1.1.12": hashes.SHA384,
           "1.2.840.113549.1.1.13": hashes.SHA512}


def verify_signature(key, algorithm, signature, data):
    oid = str(algorithm["algorithm"])
    params = bytes(algorithm["parameters"]) if algorithm["parameters"].hasValue() else b""
    if oid.startswith("1.2.840.10045.4.3.") and oid in _HASHES:
        if params or not isinstance(key, ec.EllipticCurvePublicKey):
            raise ValueError("Invalid ECDSA parameters or key")
        key.verify(signature, data, ec.ECDSA(_HASHES[oid]()))
    elif oid == "1.3.101.112":
        if params or not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError("Invalid Ed25519 parameters or key")
        key.verify(signature, data)
    elif oid in _HASHES:
        if params not in (b"", b"\x05\x00") or not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("Invalid RSA parameters or key")
        key.verify(signature, data, padding.PKCS1v15(), _HASHES[oid]())
    elif oid == "1.2.840.113549.1.1.10":
        from pyasn1_alt_modules.rfc4055 import RSASSA_PSS_params
        if not params or not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("RSA-PSS requires parameters and RSA key")
        parsed = _exact(params, RSASSA_PSS_params())
        hashes_by_oid = {"1.3.14.3.2.26": hashes.SHA1, "2.16.840.1.101.3.4.2.1": hashes.SHA256,
                         "2.16.840.1.101.3.4.2.2": hashes.SHA384, "2.16.840.1.101.3.4.2.3": hashes.SHA512}
        hash_parameters = parsed["hashAlgorithm"]["parameters"]
        if hash_parameters.hasValue() and bytes(hash_parameters) != b"\x05\x00":
            raise ValueError("Hash parameters must be NULL or absent")
        h = hashes_by_oid[str(parsed["hashAlgorithm"]["algorithm"])]()
        mgf = parsed["maskGenAlgorithm"]
        if str(mgf["algorithm"]) != "1.2.840.113549.1.1.8":
            raise ValueError("RSA-PSS requires MGF1")
        from pkix_evidence import AlgorithmIdentifier
        mgf_alg = _exact(bytes(mgf["parameters"]), AlgorithmIdentifier())
        if mgf_alg["parameters"].hasValue() and bytes(mgf_alg["parameters"]) != b"\x05\x00":
            raise ValueError("MGF hash parameters must be NULL or absent")
        if str(mgf_alg["algorithm"]) != str(parsed["hashAlgorithm"]["algorithm"]):
            raise ValueError("Unsupported RSA-PSS MGF hash")
        salt = int(parsed["saltLength"])
        if salt <= 0 or int(parsed["trailerField"]) != 1:
            raise ValueError("Unsupported RSA-PSS salt or trailer")
        key.verify(signature, data, padding.PSS(mgf=padding.MGF1(h), salt_length=salt), h)
    else:
        raise ValueError("Unsupported signature algorithm: " + oid)


def sign_bytes(key, data):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "1.2.840.10045.4.3.2", key.sign(data, ec.ECDSA(hashes.SHA256()))
    if isinstance(key, rsa.RSAPrivateKey):
        return "1.2.840.113549.1.1.11", key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "1.3.101.112", key.sign(data)
    raise ValueError("Unsupported signing key")


@dataclass
class VerificationResult:
    accepted: bool = False
    signatures: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    verified_ak_spkis: set = field(default_factory=set)


def verify_evidence(ev, *, roots=(), key_resolver=None, trusted_spkis=(), signature_only=False,
                    require_all=False, expected_nonce=None, current_time=None, extra_intermediates=(), allowed_algorithms=None):
    from pkix_evidence import decode_evidence, tagged_component_value, Certificate
    result = VerificationResult()
    try:
        if isinstance(ev, bytes):
            ev = decode_evidence(ev)
        ak_claims = validate_structure(ev)
        tbs = encoder.encode(ev["tbs"])
        if getattr(ev, "_signed_tbs_der", tbs) != tbs:
            raise ValueError("TBS model does not match signed DER")
        if expected_nonce is not None:
            nonces = [bytes(claim_value(c)) for el in ev["tbs"]["reportedElements"]
                      if str(el["elementType"]) == OIDS["id-evidence-element-transaction"]
                      for c in el["claims"] if str(c["claimType"]) == OIDS["id-evidence-claim-transaction-nonce"]]
            if nonces != [expected_nonce]:
                raise ValueError("Missing or mismatched verifier nonce")
        intermediates = list(extra_intermediates)
        if ev["intermediateCertificates"].hasValue():
            intermediates += [x509.load_der_x509_certificate(encoder.encode(c)) for c in ev["intermediateCertificates"]]
    except Exception as exc:
        result.errors.append(str(exc))
        return result
    subject, cert_keys = None, set()
    def record_identity(cert):
        nonlocal subject
        dn = cert.subject.public_bytes()
        if subject is None:
            subject = dn
        elif subject != dn:
            result.errors.append("Different Attester identities")
        raw = decoder.decode(cert.public_bytes(serialization.Encoding.DER), asn1Spec=Certificate())[0]
        key_bytes = encoder.encode(raw["tbsCertificate"]["subjectPublicKeyInfo"])
        try:
            key_bytes = spki_bytes(cert.public_key())
        except Exception:
            pass
        if key_bytes in cert_keys:
            result.errors.append("Signing certificates must contain distinct SPKIs")
        cert_keys.add(key_bytes)
    for block in ev["signatures"]:
        try:
            embedded_identity = block["sid"]["certificate"].hasValue()
            if embedded_identity:
                raw_cert = encoder.encode(tagged_component_value(Certificate(), block["sid"]["certificate"]))
                record_identity(x509.load_der_x509_certificate(raw_cert))
            key, cert = resolve_signer(block["sid"], intermediates, key_resolver)
            spki = spki_bytes(key)
            if cert is not None and not embedded_identity:
                record_identity(cert)
            if ak_claims and spki not in ak_claims:
                result.errors.append("Signer not present in ak-spki claims")
            if cert is not None:
                check_certificate(cert)
                now = current_time or datetime.now(timezone.utc)
                if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
                    raise ValueError("Signer certificate is not valid at verification time")
            if allowed_algorithms is not None and str(block["signatureAlgorithm"]["algorithm"]) not in allowed_algorithms:
                raise ValueError("Signature algorithm excluded by appraisal policy")
            verify_signature(key, block["signatureAlgorithm"], bytes(block["signatureValue"]), tbs)
            if roots:
                if cert is None:
                    raise ValueError("Certificate required for path validation")
                verify_path(cert, intermediates, roots, current_time)
            elif not signature_only and spki not in trusted_spkis:
                raise ValueError("No trusted path or pinned signer SPKI")
            result.signatures.append(None)
            if spki in ak_claims:
                result.verified_ak_spkis.add(spki)
        except (UnresolvedKeyID, InconsistentSID) as exc:
            result.errors.append(str(exc))
            result.signatures.append(str(exc))
        except Exception as exc:
            result.signatures.append(str(exc) or type(exc).__name__)
    result.accepted = (not result.errors and any(s is None for s in result.signatures)
                       and (not require_all or all(s is None for s in result.signatures)))
    return result
