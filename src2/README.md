# Python Reference Implementation

## Introduction

This directory contains a Python reference implementation for the PKIX Evidence ASN.1 structures defined in `Pkix-Key-Attest-2025.asn`.

## Claude

### pkix_evidence.py

Claude was asked to generate a parser/verifier based on the ASN.1 modulde Pkix-Key-Attest-2025.asn. The following information was provided:

```txt
pip install pyasn1 pyasn1-modules cryptography

# Generate a sample DER and validate it
python pkix_evidence.py --sample --out sample.der
python pkix_evidence.py sample.der

# Parse any Evidence DER file you have
python pkix_evidence_2025.py attestation.der

# Programmatic use
from pkix_evidence_2025 import parse_evidence, validate_evidence
ev = parse_evidence(open("attestation.der","rb").read())
vr = validate_evidence(ev)
print(vr.ok, vr.errors)
```

```sh
$ sudo apt install python3-pyasn1 python3-pyasn1-modules python3-asn1crypto
```

### generalized_time_validator.py

Because the validation routine in pkix_evidence.py was erroneous when processing structures of type GeneralizedTime, Claude was asked to create a validator for GeneralizedTime.

