# Go Implementation of draft-ietf-rats-pkix-key-attestation

This document describes the Go implementation of the "Evidence Encoding for Hardware Security Modules" from
`draft-ietf-rats-pkix-key-attestation`.

## Overview

The implementation provides the following:

- **ASN.1 structures and OIDs** according to `Pkix-Key-Attest-2025.asn`
- **Parser/decoder** for DER/PEM/Base64-encoded Evidence
- **Validation** of the most important structural rules from the specification
- **Signature verification** for RSA (PKCS#1 v1.5), RSA-PSS, ECDSA, and Ed25519
- **CLI** for decode/validate/verify plus a sample generator

Source code:

- CLI: `go-src/cmd/pkix-evidence/main.go`
- Evidence logic: `go-src/pkg/evidence/*.go`

## Implementation

### Data Model

The core structures are defined in `go-src/pkg/evidence/types.go` and map directly to the ASN.1 structures:

- `PkixEvidenceRaw` (envelope with `tbs`, `signatures`, `intermediateCertificates`)
- `TbsPkixEvidence`
- `ReportedEntity`
- `ReportedClaim`
- `SignatureBlock` / `SignerIdentifier`

OIDs are defined in `go-src/pkg/evidence/oids.go`. In addition, metadata (`ClaimSpecs`)
is provided for known claim types so that decode output can use readable names.

### Parsing/Decoding

- `ReadEvidence` detects DER/PEM/Base64 automatically, or via explicit `-format`
- `Parse` decodes Evidence and returns both the structured form and the DER for the TBS block
- `DecodeClaimValue` interprets context-specific claim values (`bytes`, `utf8String`, `bool`, `time`, `int`, `oid`)
- `EvidenceToJSON` serializes the data into readable JSON

### Validation

`Validate` checks, among other things:

- `version == 1`
- only one transaction entity and only one platform entity
- repeated claims according to the specification
- key entities must contain at least one `identifier`
- duplicate key identifiers across multiple key entities are detected

### Signature Verification

`VerifyEvidence` verifies signatures against:

- signer certificate (`SignerIdentifier.certificate`) or SPKI
- optionally: certificate chain validation against trust anchors (`-verify-chain -ca`)
- optionally: binding to `transaction.ak-spki`

Supported algorithms:

- RSA (PKCS#1 v1.5): SHA-1/256/384/512
- RSA-PSS
- ECDSA: SHA-256/384/512
- Ed25519

## Usage (CLI)

Build:

```bash
go build ./go-src/cmd/pkix-evidence
```

### Decode

```bash
./pkix-evidence decode -in <file|-> [-format auto|der|pem|base64]
```

Outputs JSON with entities and claims.

### Validate

```bash
./pkix-evidence validate -in <file|-> [-format auto|der|pem|base64]
```

Outputs `ok` or a list of validation errors.

### Verify

```bash
./pkix-evidence verify -in <file|-> [-format auto|der|pem|base64] [-ca <pem>] [-verify-chain] [-require-all]
```

- `-verify-chain` verifies signer certificates against trust anchors from `-ca`
- `-require-all` requires all signatures to be valid

### Generate (Sample)

A small unsigned sample in the current format:

```bash
./pkix-evidence generate -out <file|-> [-format der|pem|base64]
```

A signed sample (ECDSA P-256, self-signed certificate) including `transaction.ak-spki`:

```bash
./pkix-evidence generate -out <file|-> -format der -signed
```

With external key/certificate input (PEM):

```bash
./pkix-evidence generate -out <file|-> -format der -signed -key signer.key -cert signer.crt
```

Optionally, `transaction.ak-spki` can be omitted:

```bash
./pkix-evidence generate -out <file|-> -format der -signed -with-ak-spki=false
```

## Tests / Test Run

A simple test run was performed to check the CLI against a generated sample:

```bash
./pkix-evidence generate -out /tmp/sample-evidence.der -format der
./pkix-evidence decode -in /tmp/sample-evidence.der
./pkix-evidence validate -in /tmp/sample-evidence.der
```

Result:

- `decode` returns valid JSON
- `validate` returns `ok`

Note: the sample is **unsigned** (`Signatures` is empty). For signature tests, Evidence
must be generated or supplied with signatures present.

### Signature Tests (Description)

For signature tests, Evidence with at least one `SignatureBlock` is required, as well as
a trust anchor (CA) that validates the signer certificate. The CLI supports two levels:

1. **Signature verification** against the certificate or SPKI contained in the `SignatureBlock`
2. **Certificate chain verification** against trust anchors (`-verify-chain -ca`)

Example flow (conceptual):

```bash
# Evidence (DER/PEM/Base64) is available and contains at least one signature
./pkix-evidence verify -in evidence.der

# Optional: also verify the certificate chain against trust anchors
./pkix-evidence verify -in evidence.der -verify-chain -ca roots.pem

# Optional: require all signatures to be valid
./pkix-evidence verify -in evidence.der -require-all
```

Expected behavior:

- For a valid signature: `signature[i]: ok`
- For an invalid signature: `signature[i]: <error>`
- If signatures are missing: warning `evidence is unsigned`
- With `ak-spki` binding: warning if no signer SPKI matches `transaction.ak-spki`

### Signature Tests (Sample with Embedded Signature)

The CLI can generate a signed sample and verify it directly:

```bash
./pkix-evidence generate -out /tmp/sample-evidence-signed.der -format der -signed
./pkix-evidence verify -in /tmp/sample-evidence-signed.der
```

Expected result:

```text
signature[0]: ok
```
