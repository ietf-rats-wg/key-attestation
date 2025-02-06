# Conceptual Model

The attestation data described here is self-attested evidence where the attesting environment is the slice of a complete device that can be thought of as the "HSM application layer" -- ie the layer of a trusted device that handles and manages private key material on behalf of other applications that make use of these keys. How this attestation data composes with other attestation layers, for example a hardware root of trust in which this environment is running, or applications that make use of the managed keys, is out of scope and can be accomplished with other wrapper formats such as RATS CMW.

The goal of this draft is for an HSM to be able to describe either a single key that it manages -- for example to accompany a Certificate Signing Request (CSR) -- or a set of keys that it manages -- for example to audit all keys within the device.

Conceptually the data that needs to be conveyed breaks into several categories:

1. Key description -- public key, key ID, fingerprint.
    1. Key protection properties -- non-exportable, etc.
    1. Key environment -- partition, cloud tenant, policy group, etc to which this key belongs.
1. Platform description -- description of the hardware, software, and global configuration state of the attesting environment in which this key resides.



# Information Model

```
TbsPkixKeyAttestation ::= SEQUENCE {
    version INTEGER,
    keys SEQUENCE SIZE (1..MAX) OF SingleKeyAttestation,
    platformClaims SEQUENCE SIZE (0..MAX) OF PlatformClaim,
}

PkixKeyAttestation ::= SEQUENCE {
    tbs TbsPkixKeyAttestation,
    signatures SEQUENCE SIZE (0..MAX) of SignatureBlock
}

SingleKeyAttestation ::= SEQUENCE {
    keyDescription KeyDescription,
    protectionClaims SEQUENCE SIZE (0..MAX) of KeyProtectionClaim,
    environment SEQUENCE SIZE (0..MAX) of KeyEnvironmentDescription
}

KeyDescription ::= SEQUENCE {
    spki        [0] SubjectPublicKeyInfo OPTIONAL,
    fingerprint [1] Fingerprint OPTIONAL,
    keyID       [2] IA5String OPTIONAL,
    description [3] UTF8String
}

Fingerprint ::= SEQUENCE {
    hashAlg AlgorithmIdentifier,
    value OCTET STRING
}

KeyEnvironmentDescription ::= SEQUENCE {
    environmentID [0] IA5String OPTIONAL,
    description   [1] UTF8String OPTIONAL
}

SignatureBlock ::= SEQUENCE {
   certChain SEQUENCE of Certificate,
   signatureAlgorithm AlgorithmIdentifier,
   signatureValue OCTET STRING
}

```


The following PlatformClaims are registered by this document, but this list is open-ended and extensible.

| Claim | OID    | Data Type       | Multiple allowed  |  Description |
| ----- | ----   | ---             | ---               | ---         |
| hwserial | TBD | String | No                | This document | The serial number of the device, as marked on the case, device certificate or other location. We should find and reference the NIST document that defines what is "FIPS Mode". |
| fipsboot | TBD | Boolean | No               | This document | Indicates whether the cryptographic module was booted and is currently running in FIPS mode. |
| envDescription | TBD | String | Yes               | Further description of the environment beyond hwvendor, hwmodel, hwserial, swversion; for example if there is a need to describe multiple logical partitions within the same device. Contents could be a human-readable description or other identifiers. |
| userModules    | TBD | SEQUENCE of KeyEnvironmentDescription | No    | An HSM typically has supports 3rd party applications to run in a protected zone within the HSM hardware boundary, typically for security-sensitive applications or to build higher-level cryptographic primitives. This claim MAY list all such modules loaded on the device, and MUST list all modules currently running that have access to the attested keys (i.e. a user module MAY be omitted if it has no relevance to the keys being attested). |
| nonce | TBD | String | No                | ?? | A nonce for the purposes of freshness of this token. EDNOTE: surely such a thing already exists in EAT? |
| attestationTime | TBD | DateTime | No             | JWT "iat" | The time at which this token was generated. EDNOTE: Surely such a thing already exists in EAT? |




The following KeyProtectionClaims are registered by this document, but this list is open-ended and extensible. Multiple copies of any KeyProtectonClaim is not allowed.

| Claim  | OID | Data Type | Definition | Description |
| ---    | --- | ---       | ---        | ---         |
| purpose | TBD | Enum {Sign, Verify, Encrypt, Decrypt, Wrap, Unwrap, Encapsulate, Decapsulate, Derive} | ??          | Defines the intended usage for this key. |
| extractable | TBD | Boolean | [PKCS11] CKA_EXTRACTABLE | Indicates if the key is able to be exported from the module. |
| neverExtractable | TBD | Boolean | [PKCS11] CKA_NEVER_EXTRACTABLE | Indicates if the key was in the past able to be exported from the module. |
| imported | TBD | Boolean | This document | Indicates if the key was generated outside the module and imported; ie this indicates that a software version of this key may exist outside of hardware protection. |
| keyExpiry | TBD | DateTime | This document | Indicates if the key has a usage period. |
| keyProtection | TBD | BIT MASK / Boolean Array {DualControl (0), CardControl (1), PasswordControl (2), ...} | Description of additional key protection policies around use or modification of this key. These are generalized properties and will not apply the same way to all HSM vendors. Consult vendor documentation for the in-context meaning of these flags.|




A KeyEnvironmentDescription object is intended to represent a partition, cloud tenant, security group, policy group, or other logical collection to which this key belongs. The `environmentId` SHOULD contain short machine-readable identifiers of the environment, for example UUIDs, while human-readable or larger data objects describing the environment SHOULD be placed in `description` and Base64 encoded if necessary.





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


# Samples


## Sample 1: Multiple keys

~~~aasvg
 .----------------------------------.
 | Attester                         |
 | --------                         |
 | hwmodel="RATS HSM 9000"          |
 | fipsboot=true                    |
 | .----------.  .----------------. |
 | | Key 18   |  | Key 21         | | 
 | | RSA      |  | ECDH-P256      | |
 | |          |  | Partition1     | |
 | '----------'  '----------------' |
 '----------------------------------'
~~~
{: #fig-arch title="Example of two KATs in a single PAT"}
