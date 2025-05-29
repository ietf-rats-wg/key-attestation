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
PkixAttestation ::= SEQUENCE {
    tbs TbsPkixAttestation,
    signatures SEQUENCE SIZE (0..MAX) of SignatureBlock
}

TbsPkixAttestation ::= SEQUENCE {
    version INTEGER,
    reportedEntities SEQUENCE SIZE (1..MAX) OF ReportedEntity
}

ReportedEntity ::= SEQUENCE {
    entityType         OBJECT IDENTIFIER,
    reportedAttributes SEQUENCE SIZE (1..MAX) OF ReportedAttribute
}

ReportedAttribute ::= SEQUENCE {
    attributeType      OBJECT IDENTIFIER,
    value              AttributeValue
}

AttributeValue :== CHOICE {
   bytes       [0] IMPLICIT OCTET STRING,
   utf8String  [1] IMPLICIT UTF8String,
   bool        [2] IMPLICIT BOOLEAN,
   time        [3] IMPLICIT GeneralizedTime,
   value       [4] IMPLICIT INTEGER,
   oid         [5] IMPLICIT OBJECT IDENTIFIER
}

SignatureBlock ::= SEQUENCE {
   certChain SEQUENCE of Certificate,
   signatureAlgorithm AlgorithmIdentifier,
   signatureValue OCTET STRING
}

id-pkix-attest OBJECT IDENTIFIER ::= { 1 2 3 999 }

id-pkix-attest-entity-type     OBJECT IDENTIFIER ::= { id-pkix-attest 0 }
id-pkix-attest-entity-request  OBJECT IDENTIFIER ::= { id-pkix-attest-entity-type 0 }
id-pkix-attest-entity-platform OBJECT IDENTIFIER ::= { id-pkix-attest-entity-type 1 }
id-pkix-attest-entity-key      OBJECT IDENTIFIER ::= { id-pkix-attest-entity-type 2 }

id-pkix-attest-attribute-type OBJECT IDENTIFIER ::= { id-pkix-attest 1 }

id-pkix-attest-attribute-request       OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-type 0 }
id-pkix-attest-attribute-request-nonce OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-request 0 }

id-pkix-evidence-attribute-platform            OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-type 1 }
id-pkix-evidence-attribute-platform-vendor     OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 0 }
id-pkix-evidence-attribute-platform-hwserial   OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 1 }
id-pkix-evidence-attribute-platform-fipsboot   OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 2 }
id-pkix-evidence-attribute-platform-model      OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 3 }
id-pkix-evidence-attribute-platform-swversion  OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 4 }
id-pkix-evidence-attribute-platform-oemid      OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 5 }
id-pkix-evidence-attribute-platform-debugstat  OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 6 }
id-pkix-evidence-attribute-platform-uptime     OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 7 }
id-pkix-evidence-attribute-platform-bootcount  OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 8 }
id-pkix-evidence-attribute-platform-usermods   OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 9 }
id-pkix-evidence-attribute-platform-envid      OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 10 }
id-pkix-evidence-attribute-platform-envdesc    OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 11 }
id-pkix-evidence-attribute-platform-fipsver    OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 12 }
id-pkix-evidence-attribute-platform-fipslevel  OBJECT IDENTIFIER ::= { id-pkix-evidence-attribute-platform 13 }

id-pkix-attest-attribute-key                   OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-type 2 }
id-pkix-attest-attribute-key-identifier        OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-key 0 }
id-pkix-attest-attribute-key-spki              OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-key 1 }
id-pkix-attest-attribute-key-purpose           OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-key 2 }
id-pkix-attest-attribute-key-extractable       OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-key 3 }
id-pkix-attest-attribute-key-never-extractable OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-key 4 }
id-pkix-attest-attribute-key-local             OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-key 5 }
id-pkix-attest-attribute-key-expiry            OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-key 6 }
id-pkix-attest-attribute-key-protection        OBJECT IDENTIFIER ::= { id-pkix-attest-attribute-key 7 }

```

The following attributes relate to the Request entity and are registered by this document.

| Claim           | OID  | Data Type | Multiple allowed | Definition | Description                                                  |
| --------------- | ---- | --------- | ---------------- | ---------- | ------------------------------------------------------------ |
| nonce           | TBD  | Bytes     | No               | ??         | A nonce for the purposes of freshness of this token. EDNOTE: surely such a thing already exists in EAT? |
| attestationTime | TBD  | DateTime  | No               | JWT "iat"  | The time at which this token was generated. EDNOTE: Surely such a thing already exists in EAT? |




The following PlatformClaims are registered by this document, but this list is open-ended and extensible.

| Claim | OID    | Data Type       | Multiple allowed  |  Definition | Description |
| ----- | ----   | ---             | ---               | ---        | ---         |
| hwserial | TBD | String | No                | This document | The serial number of the device, as marked on the case, device certificate or other location. |
| fipsboot | TBD | Boolean | No               | This document | Indicates whether the cryptographic module was booted and is currently running in FIPS mode. |
| envDescription | TBD | String | Yes               | Further description of the environment beyond hwvendor, hwmodel, hwserial, swversion; for example if there is a need to describe multiple logical partitions within the same device. Contents could be a human-readable description or other identifiers. ||
| currentTime | TBD | DateTime | No             | JWT "iat" | The time at which this token was generated. EDNOTE: Surely such a thing already exists in EAT? |
| fwVersion | TBD | String | No |  |  |




The following KeyProtectionClaims are registered by this document, but this list is open-ended and extensible. Multiple copies of any KeyProtectonClaim is not allowed.

| Claim  | OID | Data Type | Definition | Description |
| ---    | --- | ---       | ---        | ---         |
| purpose | TBD | Enum {Sign, Verify, Encrypt, Decrypt, Wrap, Unwrap, Encapsulate, Decapsulate, Derive} | ??          | Defines the intended usage for this key. |
| extractable | TBD | Boolean | [PKCS11] CKA_EXTRACTABLE | Indicates if the key is able to be exported from the module. |
| neverExtractable | TBD | Boolean | [PKCS11] CKA_NEVER_EXTRACTABLE | Indicates if the key was in the past able to be exported from the module. |
| local | TBD | Boolean | This document | Indicates if the key was generated within the module. |
| keyExpiry | TBD | DateTime | This document | Indicates if the key has a usage period. |
| keyProtection | TBD | BIT MASK / Boolean Array {DualControl (0), CardControl (1), PasswordControl (2), ...} | Description of additional key protection policies around use or modification of this key. These are generalized properties and will not apply the same way to all HSM vendors. Consult vendor documentation for the in-context meaning of these flags.||




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

## Sample 1

In the following example, four entities are defined based on three types:

- platform : This groups the attributes associated with the platform itself (the attesting environment).
- request : This groups the attributes associated with the attestation request.
- key : An entity of type "key" groups together the attributes associated with a single secret key managed by the HSM.

~~~aasvg
+---------------------------------------------------+
|   Attester                                        |
|                                                   |
|  +---------------------------------------------+  |
|  | Platform                                    |  |
|  |                                             |  |
|  |    serial="HSM-123"                         |  |
|  |    fips-boot=True                           |  |
|  |    description="Model ABC"                  |  |
|  |    fw-version="3.1.9"                       |  |
|  |    time=2025-02-03 22:34Z                   |  |
|  +---------------------------------------------+  |
|  +---------------------------------------------+  |
|  | Request                                     |  |
|  |                                             |  |
|  |    nonce=0x0102030405                       |  |
|  +---------------------------------------------+  |
|  +---------------------------------------------+  |
|  | Key                                         |  |
|  |                                             |  |
|  |   id="26d765d8-1afd-4dfb-a290-cf867ddecfa1" |  |
|  |   extractable=False                         |  |
|  |   spki=...                                  |  |
|  +---------------------------------------------+  |
|  +---------------------------------------------+  |
|  | Key                                         |  |
|  |                                             |  |
|  |   id="49a96ace-e39a-4fd2-bec1-13165a99621c" |  |
|  |   extractable=True                          |  |
|  |   spki=...                                  |  |
|  +---------------------------------------------+  |
+---------------------------------------------------+
~~~