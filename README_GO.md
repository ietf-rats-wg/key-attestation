# Go implementation of PKIX Key Attestation

The implementation follows the local `draft-ietf-rats-pkix-key-attestation.md`
and `Pkix-Key-Attest-2025.asn`. The OID assignments remain provisional:
`1.3.6.1.5.5.999` for Evidence and `1.3.6.1.5.5.7.3.999` for the attestation EKU.
These are temporary substitutions for the draft's TBD assignments.

## Build and use

Run from the repository root:

```sh
go build -o pkix-evidence ./go-src/cmd/pkix-evidence
./pkix-evidence generate -out /tmp/evidence.der -nonce-hex deadbeef
./pkix-evidence decode -in /tmp/evidence.der
./pkix-evidence validate -in /tmp/evidence.der
./pkix-evidence verify -in /tmp/evidence.der -signature-only
```

Generation always signs the example and includes `transaction.ak-spki`. It uses
an ephemeral key and a self-signed certificate with the required KU/EKU unless
`-key` and `-cert` provide a matching signing key and certificate. The built-in
nonce is demonstration data; supply a verifier-generated nonce with `-nonce-hex`.
Unsigned generation and `-with-ak-spki=false` are rejected.

`-signature-only` is an explicit diagnostic mode: it checks the structure,
signature, certificate requirements and AK binding without establishing signer
trust. It does not constitute an appraisal that the signer is trusted.

For certificate path validation against configured trust anchors:

```sh
./pkix-evidence verify -in evidence.pem -ca roots.pem
```

Intermediate certificates are taken from Evidence. Their order is irrelevant.
The custom attestation EKU is checked separately from path building, including
when it is critical. Go's TLS server-auth default is not used.

For an out-of-band AK certificate and a `keyId`-based signer:

```sh
./pkix-evidence verify -in sampledata/evidence1.pem \
  -signer-cert sampledata/ak.crt -ca sampledata/ca.crt
```

Without `-ca`, `-signer-cert` explicitly pins that certificate's public key. This
also permits checking SPKI-based signers. The CLI resolves `keyId` by matching
the configured certificate's SubjectKeyIdentifier. Library callers can provide
an arbitrary `VerifyOptions.ResolveKeyID` callback instead. Resolution alone
does not establish trust; configure roots or `TrustedSPKIs` separately.

Use `-nonce-hex` on `verify` to require the expected nonce. Timestamp claims alone
are not used as proof of freshness. `-require-all` adds a stricter policy that
requires every signature block to be acceptable.

`decode`, `validate` and `verify` accept DER, standard Base64 and a single PEM
block labelled `EVIDENCE`; use `-format auto|der|base64|pem` to select the format.
`generate` supports `-format der|base64|pem`.

## Data model and validation

- `TbsEvidence` contains `ReportedElements`; each `ReportedElement` contains
  `ElementType` and `Claims`. Decode JSON uses `elements`.
- A claim carries its directly encoded universal ASN.1 value, selected by its
  OID. `key.purpose` is a `KeyPurposes` SEQUENCE OF OID, without an OCTET STRING
  wrapper. The standard catalog includes decapsulation and encapsulation.
- `intermediateCertificates` uses an EXPLICIT `[0]` wrapper.
- Version 1, nonempty signatures/elements/claims, required claim values and
  nonempty signer identifiers are enforced. Fixed envelope structures reject
  additional fields and trailing data.
- Known claims are checked for type, element ownership, repetition, valid SPKI syntax,
  FIPS level 1..4, key identifiers and distinct attestation keys. Unknown types
  are retained as opaque extension values and skipped semantically. SPKI syntax
  validation permits unknown key algorithms so an unsupported additional signer
  does not prevent accepting a supported signature.
- Repeated key identifiers within one key element are allowed; identifiers
  shared across key elements are rejected. Equal SPKIs alone do not identify
  the same addressable object.

`VerifyEvidence` always runs structural validation and verifies that the decoded
TBS model matches the original signed DER. `VerifyResult.Accepted` is the final
policy decision. `SignatureResults` describe individual blocks, while
`ChainErrors` and `EKUErrors` are diagnostics rather than global vetoes.
`VerifiedAKSPKIs` contains only claim values backed by acceptable verified blocks.
Check `Accepted` before relying on the Evidence as a whole.

## Multi-signature policy and draft interpretation

At least one acceptable signature is required. Additional invalid or unsupported
blocks do not invalidate an acceptable block by themselves. KU with
`digitalSignature`, the attestation EKU, end-entity status and certificate
validity are checked for every certificate-backed block considered for
acceptance. Subject DNs are compared by their DER encoding in both implementations.
Multiple signing certificates must have the same subject DN and
distinct public keys. All supplied SID key representations must agree.

The draft explicitly requires rejecting Evidence with an unresolved `keyId`.
This implementation follows that requirement even if another block is valid;
the apparent tension with the general one-valid-block rule remains an editorial
question for the draft. Conflicting SID fields and different Attester identities
also reject the whole Evidence.

When AK claims are present, this implementation applies a strict policy: every
resolved signer must appear in those claims. An extra AK claim without a valid
signature does not prove that key signed the Evidence. Verifiers accept absence
of the optional claims, while generators always include them as required by the
Evidence generation procedure.

The old Go OID namespace, context-tagged ClaimValue encoding and implicit
certificate wrapper are not supported as a legacy format. As required for
extensibility, an unknown OID is still treated as an opaque extension, not as a
recognized old standard claim. Consumers must check recognized claim names and
values rather than treating successful parsing as recognition.

## Algorithms and tests

Signatures: RSA PKCS#1 v1.5 with SHA-1/256/384/512, RSA-PSS with those supported
hashes, ECDSA with SHA-256/384/512, and Ed25519. Algorithm-specific parameters are
checked. RSA-PSS supports MGF1 with the same hash as the message, a positive
explicit salt length (or the ASN.1 default), and trailer field 1. Other MGF/hash
combinations and zero-length salts are reported as unsupported. Supporting SHA-1
for parsing/verification does not require a deployment to accept it: appraisal
policy can restrict algorithms with `VerifyOptions.AllowedSignatureAlgorithms`
or the CLI flag `-algorithms <oid[,oid...]>`. Python callers use
`allowed_algorithms`. The default accepts the implemented algorithms.

```sh
go test ./...
python3 -m venv src/.venv
src/.venv/bin/python -m pip install -r src/requirements.txt
PYTHON_BIN="$PWD/src/.venv/bin/python" tools/test-interop.sh
PYTHON_BIN="$PWD/src/.venv/bin/python" tools/test-interop-negative.sh
```

The Python path tests require the system OpenSSL 3 executable. Tests create
public certificates and Evidence in temporary directories; private keys stay in
memory and repository samples are not overwritten. Coverage includes both
implementation directions, independently transcribed DER values, explicit
certificate tagging, claims and decoded values, keyId/SPKI signers, critical EKU,
multiple algorithms and signers, and malformed Evidence with valid signatures.
