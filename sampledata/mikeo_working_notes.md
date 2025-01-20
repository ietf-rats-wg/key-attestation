# Design Goals

## Information Model (Semantics)


## Data Model (Syntax)

* All claims in EAT are valid.
* Add a set of platform claims that are useful to HSMs.
* Add a set of "key attestation" claims that describe the protection properties of a private key.


Each claim must appear only once in a given token.

Claims allowed in a PKIX_PAT token:


| Claim | Data Type | Definition | Description |
| ----- | ----      | ---       | ---         |
| hwserial | String | This document | The serial number of the device, as marked on the case, device certificate or other location. |
| fipsboot | Boolean | This document | Indicates whether the cryptographic module was booted and is currently running in FIPS mode. |
| nestedTokens | Nested token | This document | Tokens for any sub-subjects such as subordinate logical or physical partitions, keys that this platform wishes to attest, etc. In a JWT or CWT EAT token, this will contain a CMW object, in a DWT this will directly contain an ASN.1 object without a CMW wrapper (ie there is no need to support JWT / CWT EAT tokens inside DWT tokens). |
| envDescription | String | Further description of the environment beyond hwvendor, hwmodel, hwserial, swversion; for example if there is a need to describe multiple logical partitions within the same device. Contents could be a human-readable description or other identifiers. |
| nonce | String | ?? | A nonce for the purposes of freshness of this token. EDNOTE: surely such a thing already exists in EAT? |
| attestationTime | DateTime | JWT "iat" | The time at which this token was generated. EDNOTE: Surely such a thing already exists in EAT? |

Claims allowed in a PKIX_KAT token:


| Claim | Data Type | Definition | Description |
| ----- | ----      | ---       | ---         |
| keyID | String    | This document | Identifies the subject key, with a vendor-specific format constrained to ASCII |
| keyDescription | String | Further description of the key beyond keyID human-readable description or other identifiers. |
| pubKey | Bytes (OCTET STRING / SPKI) | This document | Represents the subject public key being attested. |
| keyFingerprintAlg | AlgorithmID | This document | The digest algorithm used to compute the key fingerprint. |
| keyFingerprint | OCTET STRING | This document | The fingerprint of the key. |
| purpose | Enum (CHOICE) {Sign, Verify, Encrypt, Decrypt, Wrap, Unwrap, Encapsulate, Decapsulate, Derive} | ??          | Defines the intended usage for this key. |
| extractable | Boolean | [PKCS11] CKA_EXTRACTABLE | Indicates if the key is able to be exported from the module. |
| neverExtractable | Boolean | [PKCS11] CKA_NEVER_EXTRACTABLE | Indicates if the key was in the past able to be exported from the module. |
| imported | Boolean | This document | Indicates if the key was generated outside the module and imported; ie this indicates that a software version of this key may exist outside of hardware protection. |
| keyExpiry | DateTime | This document | Indicates if the key has a usage period. |


The signature block is optional on a KAT, ie it MAY be signed so that the KAT is a standalone token, or the signature MAY be omitted if the KAT is contained within a PAT where the PAT signer has authority for both the PAT and KAT claims.

All claims defined under PKIX_PAT are also allowed within a PKIX_KAT token -- in this way, an attester MAY produce a single flat token which contains both PAT and KAT claims.

RECOMMENDED parsing logic: verifiers searching for key attestation claims SHOULD peform a depth-first recursive parsing by searching nested tokens for a keyID, SPKI, or key fingerprint matching the subject key they wish attestation of, and then searching for accompanying platform data first within the same token and then up the recursion stack towards the outer-most tokens. If the same claim appears at multiple levels with conflicting values -- for example fipsBoot=false within the inner-most KAT but fips-boot=true within the containing PAT, then the value of the innermost token SHOULD be taken as applying to that key. This allows the attester to convey, for example, that the overall device might be in FIPS mode, but that particular sub-module is not.

### References

IE places to go digging for concepts of "private key protection properties"

* (DONE) PKCS#11 v3.2
* KMIP?
* (DONE) Crypto4A QASM Attest
* nShield Attestaton docs
 * https://nshielddocs.entrust.com/app-notes/key-attestation-format/construction.html
 * https://nshielddocs.entrust.com/key-attestation-docs/v1.0.2/examples.html
* CoRIM ?


## DWT Envelop Format

* Generally, we are trying to design a DER encoded equivalent of JWT / CWT.
* Dual-signing.
* Attestation type OID ?? -- could probably cross over with a CMW registry
  * PKIX_PAT
  * PKIX_KAT
* Nested attestations.




# Example

## Single KAT

In a pseudo-json format

```
{
  "keyID": "18",
  "pubKey": <SPKI>,
  "keyFingerprintAlg": AlgorithmID(id-sha256),
  "keyFingerprint": 0x1a2b3c,
  "purpose": {Sign},
  "extractable": true,
  "neverExtractable": false,
  "imported": false
}
.
// Signatures: 
{
  {
    "signingCert": <x509Certificate>,
    "signatureAlgorithm": <AlgorithmID>,
    "signature": <OCTET STRING>
  },
  {
    "signingCert": <x509Certificate>,
    "signatureAlgorithm": <AlgorithmID>,
    "signature": <OCTET STRING>
  }
}
```

## PAT containing multiple KATs

This example shows a pair of Key Attestation Tokens (KATs) nested inside a Platform Attestation Token (PAT) which might result from an attesting environment structured like this:

~~~aasvg
 |--------------------------------------|
 | .----------------------------------. |
 | | Attester                         | |
 | | --------                         | |
 | | AK Certs                         | |
 | | hwmodel="RATS HSM 9000"          | |
 | | fipsboot=true                    | |
 | | .-------------.  .-------------. | |
 | | | Key 18      |  | Key 21      | | |
 | | | RSA         |  | ECDH-P256   | | |
 | | '-------------'  '-------------' | |
 | '----------------------------------' |
 |                                      |
 |               Root of Trust (RoT)    |
 |--------------------------------------|
~~~
{: #fig-arch title="Example of two KATs in a single PAT"}

In a pseudo-json format

```
TODO: add some more EAT claims

{
  "hwvendor": "IETF RATS",
  "hwmodel": "RATS HSM 9000",
  "swversion": "1.2.3",
  "hwserial": "1234567",
  "fipsboot": false,
  "nonce": "987654321",
  "attestationTime: 2025-01-17-08-33-56,
  nestedTokens: {
    {"keyID": "18", "pubKey": <SPKI>, "keyFingerprintAlg": AlgorithmID(id-sha256), "keyFingerprint": 0x1a2b3c, "purpose": {Sign}, "extractable": false, "neverExtractable": false, "imported": false, }
    .
    { {"signingCert": <x509Certificate>, "signatureAlgorithm": <AlgorithmID>, "signature": <OCTET STRING> },
      { "signingCert": <x509Certificate>, "signatureAlgorithm": <AlgorithmID>,"signature": <OCTET STRING> } },
    {"keyID": "21", "pubKey": <SPKI>, "keyFingerprintAlg": AlgorithmID(id-sha256), "keyFingerprint": 0xc3b2a1, "purpose": {Decapsulate}, "extractable": true, "neverExtractable": false, "imported": true, }
    .
    { {"signingCert": <x509Certificate>, "signatureAlgorithm": <AlgorithmID>, "signature": <OCTET STRING> },
      { "signingCert": <x509Certificate>, "signatureAlgorithm": <AlgorithmID>,"signature": <OCTET STRING> } }
}
.
// Signatures: 
{
  {
    "signingCert": <x509Certificate>,
    "signatureAlgorithm"
    "signature": <OCTET STRING>
  },
  {
    "signingCert": <x509Certificate>,
    "signatureAlgorithm"
    "signature": <OCTET STRING>
  }

```



## PAT containing multiple KATs

This example shows an attesting environment where an application key ("Key 18") is contained directly within the root of trust which is running in FIPS mode, and also there is a partition within the device which is not running in FIPS mode and which contains a partition root key ("Partition1-RootKey").

The purpose of this example is to show how PAT properties can be overridden by nested tokens. Correct parsing of this token will show that both keys "Key 18" and "Partition1-RootKey" are on the same device but "Key 18" is protected in FIPS mode while "Partition1-RootKey" is not.

This example also shows that while we conceptually break claims into "platform claims" and "key claims", in pratcise they can be interleaved in any way that makes sense for the attesting environment; for example the token for "Partitian 1" contains claims that attest both the platform "Partition 1" as well as attesting the key "Partition1-RootKey".

~~~aasvg
 |-------------------------------------------|
 | .---------------------------------------. |
 | | Attester                              | |
 | | --------                              | |
 | | AK Certs                              | |
 | | hwmodel="RATS HSM 9000"               | |
 | | fipsboot=true                         | |
 | | .----------.  .---------------------. | |
 | | | Key 18   |  | Partition 1         | | | 
 | | | RSA      |  | fipsboot=false      | | |
 | | |          |  | Partition1-RootKey  | | |
 | | |          |  | ECDH-P256           | | |
 | | '----------'  '---------------------' | |
 | '---------------------------------------' |
 |                                           |
 |               Root of Trust (RoT)         |
 |-------------------------------------------|
~~~
{: #fig-arch title="Example of two KATs in a single PAT"}

In a pseudo-json format

```
TODO: add some more EAT claims

{
  "hwvendor": "IETF RATS",
  "hwmodel": "RATS HSM 9000",
  "swversion": "1.2.3",
  "hwserial": "1234567",
  "fipsboot": false,
  "nonce": "987654321",
  "attestationTime: 2025-01-17-08-33-56,
  nestedTokens: {
    {"keyID": "18", "pubKey": <SPKI>, "keyFingerprintAlg": AlgorithmID(id-sha256), "keyFingerprint": 0x1a2b3c, "purpose": {Sign}, "extractable": false, "neverExtractable": false, "imported": false, }
    .
    { {"signingCert": <x509Certificate>, "signatureAlgorithm": <AlgorithmID>, "signature": <OCTET STRING> },
      { "signingCert": <x509Certificate>, "signatureAlgorithm": <AlgorithmID>,"signature": <OCTET STRING> } },
    {"keyID": "21", "pubKey": <SPKI>, "keyFingerprintAlg": AlgorithmID(id-sha256), "keyFingerprint": 0xc3b2a1, "purpose": {Decapsulate}, "extractable": true, "neverExtractable": false, "imported": true, }
    .
    { {"signingCert": <x509Certificate>, "signatureAlgorithm": <AlgorithmID>, "signature": <OCTET STRING> },
      { "signingCert": <x509Certificate>, "signatureAlgorithm": <AlgorithmID>,"signature": <OCTET STRING> } }
}
.
// Signatures: 
{
  {
    "signingCert": <x509Certificate>,
    "signatureAlgorithm"
    "signature": <OCTET STRING>
  },
  {
    "signingCert": <x509Certificate>,
    "signatureAlgorithm"
    "signature": <OCTET STRING>
  }

```


# ASN.1 Module (DWT)


```

imports
5280: Certificate, AlgorithmID, GeneralizedTime, SubjectPublicKeyInfo

-- Envelope

PkixAttestation ::= SEQUENCE {
  version INTEGER,
  claims SetOfClaims,
  signatures SEQUENCE SIZE (0..MAX) OF SignatureBlock,
}

SignatureBlock ::= SEQUENCE {
   certChain SEQUENCE of Certificate,
   signatureAlgorithm AlgorithmIdentifier,
   signatureValue OCTET STRING
}

PkixClaim ::= SEQUENCE {
  type ::= Object Identifier,
  value ::= Any
}

SetOfClaims ::= SEQUENCE SIZE (0..MAX) OF PkixClaim


-- Claims
TODO: define OIDs and ASN.1 for all the EAT claims.

pkixattestarc ::= Object Identifier {1 2 3 999}

id-pkixattest-hwserial ::= Object Identifier {pkixattestarc 1}
pkixclaim-hwSerial ::= IA5String

id-pkixattest-fipsboot ::= Object Identifier {pkixattestarc 2}
pkixclaim-fipsboot ::= boolean

id-pkixattest-nestedTokens ::= Object Identifier {pkixattestarc 3}
pkixclaim-nestedTokens ::= SEQUENCE of PkixAttestation

id-pkixattest-nonce ::= Object Identifier {pkixattestarc 4}
pkixclaim-nonce ::= IA5String

id-pkixattest-attestationTime ::= Object Identifier {pkixattestarc 5}
pkixclaim-attestationTime ::= GeneralizedTime

id-pkixattest-keyid ::= Object Identifier {pkixattestarc 6}
pkixclaim-keyID ::= IA5String

id-pkixattest-pubKey ::= Object Identifier {pkixattestarc 7}
pkixclaim-pubKey ::= SubjectPublicKeyInfo

id-pkixattest-keyFingerprintAlg ::= Object Identifier {pkixattestarc 8}
pkixclaim-keyFingerprintAlg ::= AlgorithmID

id-pkixattest-keyFingerprint ::= Object Identifier {pkixattestarc 9}
pkixclaim-keyFingerprint ::= OCTET STRING


TODO: this should be a bit mask similar to KeyUsage,
      But I don't understand how you bit mask these together in the python
      IE I think the python example that I borrowed fram pyasn1-alt-modules/rfc5280.py is wrong.

id-pkixattest-purpose ::= Object Identifier {pkixattestarc 10}
pkixclaim-purpose ::= BIT STRING {
  sign (0),
  verify (1),
  Encrypt (2), 
  Decrypt (3),
  Wrap (4),
  Unwrap (5),
  Encapsulate (6),
  Decapsulate (7),
  Derive (8)
  }
}

    <!-- Value.namedValues = namedval.NamedValues(
        ('Sign', 0),
        ('Verify', 1),
        ('Encrypt', 2),
        ('Decrypt', 3),
        ('Wrap', 4),
        ('Unwrap', 5),
        ('Encapsulate', 6),
        ('Decapsulate', 7),
        ('Derive', 8)
    ) -->

id-pkixattest-extractable ::= Object Identifier {pkixattestarc 11}
pkixclaim-extractable ::= boolean

id-pkixattest-neverExtractable ::= Object Identifier {pkixattestarc 12}
pkixclaim-neverExtractable ::= boolean

id-pkixattest-imported ::= Object Identifier {pkixattestarc 13}
pkixclaim-imported ::= boolean

id-pkixattest-keyexpiry ::= Object Identifier {pkixattestarc 14}
pkixclaim-keyExpiry ::= GeneralizedTime

id-pkixattest-keydescription ::= Object Identifier {pkixattestarc 15}
pkiclaim-keyDescription ::= UTF8String
```

## Signing and Verification Process

Signatures are computed over the DER encoded `SetOfClaims` object. Thus the PkixAttestation version number and `SignatureBlock` metadata are not protected.


# Verification Profiles

## CA/Browser Forum Code-Signing Baseline Requirements

... intro text

The subscriber MUST:

* Provide the CA with a CSR containing the subscriber key.
* Provide an attestation token as per this specification describing the private key protection properties of the subscriber's private key. This token MAY be transported inside the CSR as per draft-ietf-lamps-csr-attest, or it MAY be transported adjacent to the CSR over any other certificate enrollment mechanism.

The CA / RA / RP / Verifier MUST:

* Ensure that the subscriber key which is the subject of the CSR is also described by a KAT by matching either the key fingerprint or full SubjectPublicKeyInfo.
* The hardware root-of-trust described by a PAT has a valid and active FIPS certificate according to the NIST CMVP database.
* The attestation signing key (AK) which has signed the attestation token chains to a root certificate that A) belongs to the hardware vendor described in the PAT token, and B) is trusted by the CA / RA / RP / Verifier to endorse hardware from this vendor, for example through a CA's partner program or through a network operator's device onboarding process.
* The key is protected by a module running in FIPS mode. The parsing logic is to start at the leaf KAT token that matches the key in the CSR and parsing towards the root PAT ensuring that there is at least one `fipsboot=true` and no `fipsboot=false` on that path.


## Additional Verification Profiles

The community is encouraged to define additional verification profiles to satisfy other use-cases or regulations.
