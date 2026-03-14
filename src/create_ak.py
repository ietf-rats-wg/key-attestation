from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate_ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def save_cert_pem(cert: x509.Certificate, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def build_name(common_name: str, ou: str , o: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def create_root_ca(ca_cert_file: Path) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    private_key = generate_ec_key()
    subject = issuer = build_name("RootCA", "pkix-key-attestation", "ietf-rats")

    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )

    save_cert_pem(cert, ca_cert_file)

    return private_key, cert


def create_int_ca(
    ca_private_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    int_cert_file: Path,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    private_key = generate_ec_key()
    subject = build_name("IntCA", "pkix-key-attestation", "ietf-rats")

    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    save_cert_pem(cert, int_cert_file)

    return private_key, cert


def create_end_entity_cert(
    ca_private_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    ak_cert_file: Path,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    private_key = generate_ec_key()
    subject = build_name("test-ak", "pkix-key-attestation", "ietf-rats")
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    save_cert_pem(cert, ak_cert_file)

    return private_key, cert


def generateCerts() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate, x509.Certificate]:
    """
    Returns the ak.key, ak.crt, and ca.crt.
    Saves the ak.crt and ca.crt to disk in the /sampledata dir
    """

    # Note to whoever touches this code -- don't ever save the private keys to disk.
    # It has happened before that test keys associated with reference implementations have made it into production:
    # Reference: https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem
    # Therefore, this reference implementation will generate itself fresh CA and AK keys on each run and never save them to disk.
    # (but it will save the certificates so that the sample data can be verified)

    output_dir = Path("../sampledata")
    ca_cert_file = Path(output_dir, "ca.crt")
    int_cert_file = Path(output_dir, "int.crt")
    ak_cert_file = Path(output_dir, "ak.crt")

    ca_private_key, ca_cert = create_root_ca(ca_cert_file)
    int_private_key, int_cert = create_int_ca(ca_private_key, ca_cert, int_cert_file)
    ak_private_key, ak_cert = create_end_entity_cert(int_private_key, int_cert, ak_cert_file)

    return ak_private_key, ak_cert, ca_cert


def main():
    generateCerts()


if __name__ == "__main__":
    main()