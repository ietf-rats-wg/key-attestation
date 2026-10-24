The scripts in this directory are a reference implementation that generates the sample data in the `/sampledata` dir.


## Current draft implementation

`pkix_evidence.py` defines the DER schema and generator. `verification.py`
validates envelopes and claims, resolves each signer's key, checks mandatory
attestation KU/EKU and certificate validity, verifies signatures, and applies
explicit trust and multi-signature policies. The provisional OIDs and policy
choices are documented in [README_GO.md](../README_GO.md); both implementations
use those choices. The signature algorithms listed there are also supported by
the Python verifier. Python generation supports ECDSA/SHA-256, RSA/SHA-256 and
Ed25519. Certificate path validation invokes the system **OpenSSL 3** executable
with purpose `any` after the separate attestation KU/EKU check.

From this directory:

```sh
make install
make check
make interop-test
make interop-test-negative
.venv/bin/python main.py --generate
```

From the repository root, an isolated installation and all tests can also be run
without using `make`:

```sh
python3 -m venv /tmp/key-attestation-venv
/tmp/key-attestation-venv/bin/python -m pip install -r src/requirements.txt
PYTHONPATH=src /tmp/key-attestation-venv/bin/python -m unittest discover -s src -v
```

The tests build the Go CLI unless `PKIX_GO_BIN` points to an existing build.
They exercise both directions and do not overwrite `sampledata`. Dependencies
are pinned to the versions used for the current test run; Python 3.10 or newer
is required.

Generate fresh public examples in a separate directory:

```sh
/tmp/key-attestation-venv/bin/python src/main.py --generate --output-dir /tmp/pkix-samples
```

The generator stages and validates all examples before copying public artifacts
to the destination. Private keys remain in memory. Example 1 uses an out-of-band
AK certificate selected by `keyId`; example 2 embeds its signer certificate;
example 3 uses a bare SPKI. Intermediate certificates use EXPLICIT tagging.

```sh
/tmp/key-attestation-venv/bin/python src/main.py --validate \
  /tmp/pkix-samples/evidence1.pem /tmp/pkix-samples/ak.crt \
  /tmp/pkix-samples/int.crt /tmp/pkix-samples/ca.crt --quiet
/tmp/key-attestation-venv/bin/python src/main.py --validate \
  /tmp/pkix-samples/evidence2.pem --ca /tmp/pkix-samples/ca.crt --quiet
/tmp/key-attestation-venv/bin/python src/main.py --validate \
  /tmp/pkix-samples/evidence3.pem /tmp/pkix-samples/ak.crt --quiet
```

Supplying an AK certificate without a CA pins its SPKI explicitly. A certificate
inside Evidence alone is not trusted. Use `--signature-only` for an explicit
cryptographic diagnostic without establishing trust, `--require-all` for the
stricter all-signatures policy, and `--nonce-hex` for a required verifier nonce.
Library users call `verify_evidence` with roots, trusted SPKIs or a keyId resolver
and inspect `VerificationResult.accepted`. Resolution is separate from trust.
Only `verified_ak_spkis` values backed by acceptable verified signature blocks
can be used as evidence that those keys signed the TBS.
