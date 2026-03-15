# Python Reference Implementation

This directory contains a Python reference implementation for the PKIX Evidence ASN.1 structures defined in `Pkix-Key-Attest-2025.asn`.

The main entry points are:

- `pkix_evidence_der.py`: builds, signs, encodes, decodes, and prints a sample PKIX Evidence object
- `create_ak.py`: generates a temporary certificate chain used by the sample evidence

When the script runs successfully, it also writes generated sample artifacts to the repository's `sampledata/` directory.

## Requirements

- Python 3.12 or newer
- Internet access for the first dependency installation

Python dependencies are listed in:

- `src/requirements.txt`

## Recommended Setup

Use a virtual environment inside `src/`:

```bash
python3 -m venv src/.venv
./src/.venv/bin/python -m pip install -r src/requirements.txt
```

## Run the Program

From the repository root:

```bash
./src/.venv/bin/python src/pkix_evidence.py
```

This performs the following steps:

1. Builds a sample `Evidence` structure
2. Generates an attestation key and certificate chain
3. Signs the TBS section
4. DER-encodes the result
5. Decodes and pretty-prints the structure
6. Verifies DER round-trip stability
7. Writes Base64-encoded evidence to `sampledata/evidence.b64`

## Using the src Makefile

Python-specific automation is intentionally kept out of the repository root `Makefile`.
Use the dedicated `src/Makefile` instead.

From the repository root:

```bash
make -C src install
make -C src check
make -C src run
make -C src interop-test
make -C src interop-test-negative
```

Meaning:

- `make -C src install`: create `src/.venv` and install Python dependencies
- `make -C src check`: syntax-check the Python files
- `make -C src run`: run `src/pkix_evidence_der.py` using the local virtual environment
- `make -C src interop-test`: run the positive interoperability test between the Python and Go implementations
- `make -C src interop-test-negative`: run negative interoperability tests and confirm that manipulated evidence is rejected by the Go implementation

If you are already in `src/`, you can use:

```bash
make install
make check
make run
make interop-test
make interop-test-negative
```

## Interoperability Tests

Two dedicated scripts are available in the repository root under `tools/`:

```bash
tools/test-interop.sh
tools/test-interop-negative.sh
```

The positive interoperability test does the following:

1. Runs the Python implementation to generate fresh evidence and certificates
2. Checks the generated certificate chain with `openssl`
3. Runs the Go implementation with `decode`, `validate`, and `verify`
4. Verifies the signer certificate chain against the generated CA certificate

Run it with:

```bash
make -C src interop-test
```

or directly:

```bash
tools/test-interop.sh
```

The negative interoperability test generates manipulated evidence and confirms that the Go implementation rejects it.

It currently covers:

- corrupted signature data
- invalid claim type encoding for `key.identifier`

Run it with:

```bash
make -C src interop-test-negative
```

or directly:

```bash
tools/test-interop-negative.sh
```

## Note on `tools/test.sh`

The repository also contains `tools/test.sh` in the repository root.

That script reproduces the document-oriented checks from the repository's Internet-Draft tooling.

It prepares a temporary workspace, copies the draft sources and related files, and runs the Docker-based `i-d-template` process used to build and validate the Internet-Draft.

## Troubleshooting

If you see an error like:

```text
ModuleNotFoundError: No module named 'pyasn1'
```

then the virtual environment is either missing or the dependencies have not been installed yet. Re-run:

```bash
./src/.venv/bin/python -m pip install -r src/requirements.txt
```

If you activate the environment first, you can also run the script more simply:

```bash
source src/.venv/bin/activate
python src/pkix_evidence.py
```
