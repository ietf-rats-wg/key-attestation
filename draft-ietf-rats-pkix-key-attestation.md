---
title: PKIX Evidence for Remote Attestation of Hardware Security Modules
abbrev: PKIX Evidence for Remote Attestation of HSMs
docname: draft-ietf-rats-pkix-key-attestation-latest

category: std
consensus: true
submissiontype: IETF

ipr: trust200902
area: "Security"
workgroup: "RATS"
keyword:
  - Internet-Draft
  - RATS
  - PKIX
  - HSM
coding: utf-8

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
  docmapping: yes
  toc_levels: 4
venue:
  group: RATS
  type: Working Group
  mail: rats@ietf.org
  arch: https://datatracker.ietf.org/wg/rats/about/
  github: "ietf-rats-wg/key-attestation"
  latest: "https://ietf-rats-wg.github.io/key-attestation/draft-ietf-rats-pkix-key-attestation.html"

author:
  - name: Mike Ounsworth
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road - Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: mike.ounsworth@entrust.com

  - name: Jean-Pierre Fiset
    org: Crypto4A Inc.
    abbrev: Crypto4A
    street: 1550A Laperriere Ave
    city: Ottawa, Ontario
    country: Canada
    code: K1Z 7T2
    email: jp@crypto4a.com

  - name: Hannes Tschofenig
    org: University of Applied Sciences Bonn-Rhein-Sieg
    abbrev: H-BRS
    country: Germany
    email: Hannes.Tschofenig@gmx.net

  - name: Henk Birkholz
    org: Fraunhofer SIT
    email: henk.birkholz@ietf.contact

  - name: Monty Wiseman
    country: United States of America
    email: mwiseman@computer.org

  - name: Ned Smith
    org: Intel Corporation
    country: United States of America
    email: ned.smith@intel.com

normative:
  RFC9334:
  RFC5280:
  RFC9711:
  RFC4648:
  X680:
    title: "Information technology — ASN.1: Specification of basic notation"
    author:
      - org: ITU-T
    target: https://www.itu.int/rec/T-REC-X.680
  X690:
    title: "Information technology — ASN.1 encoding rules: BER, CER, DER"
    author:
      - org: ITU-T
    target: https://www.itu.int/rec/T-REC-X.690
  PKCS11:
    title: "PKCS #11 Specification Version 3.1"
    author:
      - name: Dieter Bong
      - name: Tony Cox
      - org: OASIS PKCS 11 TC
    date: 2022-08-11
    target: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/cs01/pkcs11-spec-v3.1-cs01.html
  FIPS140-3:
    title: "Security Requirements for Cryptographic Modules"
    author:
      - org: NIST, Information Technology Laboratory
    seriesinfo:
      FIPS: 140-3
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf
  X.690:
    target: https://www.itu.int/rec/T-REC-X.690
    title: >
      Information technology --
      ASN.1 encoding rules: Specification of Basic Encoding Rules (BER),
      Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
    author:
    - org: ITU-T
    date: 2021-02
    seriesinfo:
      ITU-T Recommendation: X.690
      ISO/IEC: 8825-1:2021
  I-D.jpfiset-lamps-attestationkey-eku:

informative:
  RFC2986:
  RFC6024:
  RFC9019:
  RFC4211:
  I-D.ietf-lamps-csr-attestation:
  I-D.fossati-tls-attestation:
  I-D.ietf-rats-msg-wrap:
  CNSA2.0:
    title: "Commercial National Security Algorithm Suite 2.0"
    author:
      - org: National Security Agency
    target: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
  CSBR:
    title: "Baseline Requirements for the Issuance and Management of Publicly-Trusted Code Signing Certificates Version 3.8.0"
    author:
      - org: CA/Browser Forum
    target: https://cabforum.org/working-groups/code-signing/documents/

entity:
  SELF: "RFCthis"

--- abstract

This document specifies a vendor-agnostic format for Evidence produced and verified within a PKIX context.
The Evidence produced this way includes claims collected about a cryptographic module
and elements found within it such as cryptographic keys.

One scenario envisaged is that the state information about the cryptographic module can be securely presented
to a remote operator or auditor in a vendor-agnostic verifiable format.
A more complex scenario would be to submit this Evidence to a Certification Authority to aid in determining
whether the storage properties of this key meet the requirements of a given certificate profile.

This specification also offers a format for requesting a cryptographic module to produce Evidence tailored for expected use.

--- middle

# Introduction

This specification defines a format to transmit Evidence from an Attester to a Verifier within a PKIX
environment. This environment refers to the components generally used to support PKI applications
such as Certification Authorities and their clients, or more generally that rely upon X.509 certificates.
As outlined in {{terminology}}, this specification uses a necessary mixture of RATS and PKI terminology
in order to map concepts between the two domains.

Within this specification, the concepts found in the Remote ATtestation procedureS Architecture ({{RFC9334}}) are
mapped to the PKIX environment. There are many other specifications that are based on the RATS Architecture
which offer formats to carry Evidence. This specification deals with peculiar aspects of the PKIX environment
which make the existing Evidence formats inappropriate:

* ASN.1 is the preferred encoding format in this environment. X.509 certificates ({{RFC5280}}) are used
widely within this environment and the majority of tools are designed to support ASN.1. There are
many specialized devices (Hardware Security Modules) that are inflexible in adopting other formats because
of internal constraints or validation difficulties. This specification defines the format in ASN.1 to ease the
adoption within the community.

* The claims reported within the generated Evidence are generally a small subset of all possible claims about
the Target Environment. The claims relate to elements such as "platform" and "keys" which are more numerous than
what a Verifier requires for a specific function. This specification provides the means to moderate the information
disseminated as part of the generated Evidence.

This specification also aims at providing an extensible framework to encode within Evidence claims other than
the one proposed in this document. This allows implementations to introduce new claims and their associated
semantics to the Evidence produced.


# Use Cases

This section covers use cases that motivated the development of this specification.


## Remote audit of a Hardware Security Module (HSM)

There are situations where it is necessary to verify the current running state of an HSM as part of operational or
auditing procedures. For example, there are devices that are certified to work in an environment only if certain
versions of the firmware are loaded or only if user keys are protected with specific policies.

The Evidence format offered by this specification allows a platform to report its firmware level along with
other collected claims necessary in critical deployments.


## Key import and HSM clustering

Consider that an HSM is being added to a logical HSM cluster. Part of the onboarding process could involve
the newly-added HSM providing Evidence of its running state, for example that it is a genuine device from
the same manufacturer as the existing clustered HSMs, firmware patch level, FIPS mode, etc.
It could also be required to provide information about any system-level keys required to establish
secure cluster communication. In this scenario, the Verifier and Relying Party will typically be other HSMs in the cluster
deciding whether or not to admit the new HSM.

A related scenario is when performing a key export-import across HSMs.
If the key is being imported with certain properties, for example an environment running in FIPS mode at
FIPS Level 3, and the key is set to certain protection properties such as Non-Exportable and Dual-Control,
then the HSM might wish to verify that the key was previously stored under the same properties.
This specification provides an Evidence format with sufficient details to support this type of
implementation across HSM vendors.

These scenarios motivate the design requirements to have an ASN.1 based Evidence format and a data model that
more closely matches typical HSM architecture since, as shown in both scenarios,
an HSM is acting as Verifier and Relying Party.


## Attesting subject of a certificate issuance

Prior to a Certification Authority (CA) issuing a certificate on behalf of a subject, a number of procedures
are required to verify that the subject of the certificate is associated with the key that is certified.
In some cases, such as issuing a code signing certificate {{CNSA2.0}} {{CSBR}}, a CA must ensure that
the subject key is located in a Hardware Security Module (HSM).

The Evidence format offered by this specification is designed to carry the information necessary for a CA to
assess the location of the subject key along a number of commonly-required attributes. More specifically, a CA could
determine which HSM was used to generate the subject key, whether this device adheres
to certain jurisdiction policies (such as FIPS mode) and the constraints applied to the key (such as whether is it extractable).

For relatively simple HSM devices, storage properties such as "extractable" may always be false for all keys
since the devices are not capable of key export and so the attestation could be essentially a hard-coded template asserting these
immutable attributes. However, more complex HSM devices require a more complex Evidence format that encompasses the
mutability of these attributes.

Also, a client requesting a key attestation might wish to scope-down the content of the produced Evidence as
the HSM contains much more information than that which is relevant to the transaction.
Not reducing the scope of the generated Evidence could, in some scenarios, constitute a privacy violation.


# Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

This specification uses a necessary mixture of PKI terminology and RATS Architecture definitions
in order to map concepts between the two domains.

The reader is assumed to be familiar with the vocabulary and concepts
defined in the RATS Architecture ({{RFC9334}}) such as Attester,
Relying Party, Verifier.

The reader is assumed to be familiar with common vocabulary and concepts
defined in {{RFC5280}} such as certificate, signature, attribute, verification and validation.

In order to avoid confusion, this document generally
capitalizes RATS terms such as Attester, Relying Party, and Claim.
Therefore, for example, a "Verifier"
should be assumed to be an entity that checks the validity of Evidence as per {{RFC9334}},
whereas a "verifier" could be a more general reference to a PKI entity that checks
the validity of an X.509 certificate or other digital signature as per {{RFC5280}}.

The following terms are used in this document:

{: vspace="0"}

Attestation Key (AK):
: Cryptographic key controlled solely by the Attester and used only for the purpose
of producing Evidence. In other words, it is used to digitally sign the claims collected by
the Attester.

Attester:
: The term Attester respects the definition offered in {{RFC9334}}. In this specification, it
is also interchangeable with "platform" or "HSM".

Attesting Environment:
: As defined in {{RFC9334}}, the Attesting Environment collects the information to be represented
in Claims. In practical terms, an implementation may be designed with services to perform this function.
To remain consistent with the RATS Architecture, the term "Attesting Environment" is used throughout
this specification.

Evidence:
: The term Evidence respects the definition offered in {{RFC9334}}. In this specification, it
refers to claims, encoded according to the format defined within this document, and signed using
Attestation Keys.

Hardware Security Module (HSM):
: A physical computing device that safeguards and manages secrets, such as cryptographic keys,
and performs cryptographic operations based on those secrets.
This specification takes a broad definition of what counts as an HSM to include smartcards,
USB tokens, TPMs, cryptographic co-processors (PCI cards) and "enterprise-grade" or "cloud-service grade" HSMs
(possibly rack mounted). In this specification, it is interchangeable with "platform" or "Attester".

Key Attestation:
: Process of producing Evidence containing claims pertaining to user keys found within an HSM. In
general, the claims include enough information about a user key and its hosting platform to allow
a Relying Party to make judicious decisions about the key, such as whether to issue a certificate for the key.

RATS:
: Remote ATtestation procedureS. Refers to a working group within IETF and all the documents developed
under this umbrella of efforts. This specification is developed using concepts developed in RATS but more
particularly refers to the RATS Architecture as introduced in {{RFC9334}}.

Platform:
: The module or device that embodies the Attester. In this specification, it is interchangeable with
"Attester" or "HSM".

Platform Attestation:
: Evidence containing claims pertaining to measured values associated with the platform itself. In general, the claims include
enough information about the platform to allow a Relying Party to make judicious decisions about the
platform, such as those carried out during audit reviews.

Presenter:
: Role that facilitates communication between the Attester and the Verifier. The
Presenter initiates the operation of generating Evidence at the Attester and
passes the generated Evidence to the Verifier. In the case of HSMs, the Presenter
is responsible of selecting the claims that are part of the generated Evidence.

Trust Anchor:
: As defined in {{RFC6024}} and {{RFC9019}}, a Trust Anchor
"represents an authoritative entity via a public key and
associated data. The public key is used to verify digital
signatures, and the associated data is used to constrain the types
of information for which the trust anchor is authoritative." The
Trust Anchor may be a certificate, a raw public key, or other
structure, as appropriate.

Trusted Platform Module (TPM):
: A tamper-resistant processor generally located on a computer's motherboard used to enhance attestation
functions for the hosting platform. TPMs are very specialized Hardware Security Modules and generally use
other protocols (than the one presented in this specification) to transmit Evidence.

User Key:
: A user key consists of a key hosted by an HSM (the platform) and intended to be used by a client
of the HSM. Other terms used for a user key are "application key", "client key" or "operational key".
The access and operations on a user key is controlled by the HSM.

## Claims and measurements in PKIX Evidence

The RATS Architecture {{RFC9334}} states that Evidence is made up of claims and that a claim is "a piece of
asserted information, often in the form of a name/value pair". The RATS Architecture also mentions
the concept of "measurements" that "can describe a variety of attributes of system components, such
as hardware, firmware, BIOS, software, etc., and how they are hardened."

Some HSMs have a large amount of memory and can therefore contain a substantial amount of elements that
can be observed independently by the Attesting Environment. Each of those elements, in turn, can contain a
number of measurable attributes.

A certain level of complexity arises as multiple elements of the same class can be reported simultaneously in generated
Evidence. In this case, multiple similar claims are reported simultaneously but associated with different elements.

For example, two independent user keys could be reported simultaneously in Evidence. Each key is associated with a
SPKI (Subject Public Key Identifier). The measured values for the SPKI of the respective keys are different.

To that end, in this specification, the claims are organized as claim sets where each claim is the association of
a claim type with the measured value. The claim sets, in turn, are organized by entities. An entity represents one
of the elements that is observed in the Target Environment.

Thus, an entity is associated with a claim set. The claim set is a collection of claims. Each claim is a claim type
with a measured value.

The grouping of claim sets into entities facilitates the comprehension of a large addressable space into
elements recognizable by the user. More importantly, it curtails the produced Evidence to portions of the
Target Environment that relate to the needs of the Verifier. See {{sec-cons-privacy}}.


## Attestation Key Certificate Chain {#sec-ak-chain}

The data format in this specification represents PKIX Evidence and
requires third-party endorsement in order to establish trust. Part of this
endorsement is a trust anchor that chains to the HSM's attestation key (AK)
which signs the Evidence. In practice the trust anchor will usually be a
manufacturing CA belonging to the device vendor which proves
that the device is genuine and not counterfeit. The trust anchor can also belong
to the device operator as would be the case when the AK certificate is replaced
as part of onboarding the device into a new operational environment.

The AK certificate that signs the evidence MUST include the Extended Key
Usage (EKU) certificate extension, and the EKU certificate extension MUST
include the `id-kp-attest`, as defined in {{I-D.jpfiset-lamps-attestationkey-eku}}.

Note that the data format specified in {{sec-data-model}} allows for zero, one, or multiple
'SignatureBlock's, so a single Evidence statement could be un-protected, or could be endorsed by multiple
AK chains leading to different trust anchors. See {{sec-verif-proc}} for a discussion of handling multiple SignatureBlocks.


# Information Model {#sec-info-model}

The PKIX Evidence format is composed of two main sections:

* An Evidence section which describes the list of reported entities.

* A signature section where one or more digital signatures are offered to prove the origin of the
  Evidence and maintain its integrity.

The details of the signature section is left to the data model. The remainder of this section
deals with the way the information is organized to form the claims.

The claim sets are associated with entities to help with the organization and comprehension
of the information. Entities are elements observed in the Target Environment by the Attesting
Environment. Each entity, in turn, is associated with a claim set that describes the attributes
of the element.

Therefore, the Claim description section is a set of entities and each entity is composed
of a claim set.

## Entity

An entity is a logical construct that refers to a portion of the Target Environment's state. It is
addressable via an identifier such as a UUID or a handle (as expressed in [PKCS11]). In general, an
entity refers to a component recognized by users of the HSM, such as a key or the platform itself.

An entity is composed of a type, the entity type, and a claim set. The entity type
describes the class of the entity while its claim set defines its state.

An entity MUST be reported at most once in a claim description. The claim description can
have multiple entities of the same type (for example reporting multiple keys), but each
entity MUST relate to different portions of the Target Environment.

It is possible for two entities to be quite similar such as in a situation where a key is imported
twice in a HSM. In this case, the two related entities could have similar claim sets. However, they
are treated as different entities as they are reporting different portions of the Target Environment.

The number of entities reported in a claim description, and their respective type, is
left to the implementer. For a simple device where there is only one key, the list of
reported entities could be fixed. For larger and more complex devices, the list of
reported entities should be tailored to the demands of the Presenter.

In particular, note that the nonce claim contained with the Transaction entity is optional,
and therefore it is possible that an extremely simple device that holds one static key
could have its Evidence generated at manufacturing time and injected
statically into the device instead of
being generated on-demand. This model would essentially
off-board the Attesting Environment to be part of the manufacturing infrastructure. In the RATS
Architecture, this configuration would refer to the the information provided by the HSM as an Endorsement
provided by the manufacturer as opposed to Evidence generated by the Attesting Environment.


## Entity Type

An entity is defined by its type. This specification defines three entity types:

* Platform : This entity holds a claim set that describes the state of the platform (or device)
  itself. Entities of this type hold claims that are global
  in nature within the Target Environment.

* Key : The entities of this type represent a cryptographic key protected within the
  Target Environment and hold a claim set that describes that specific key.

* Transaction : This entity is logical in nature since it is associated with a claim set
  that does not describe anything found in the Target Environment. Instead, this claim set
  relates to the current request for Evidence such as a nonce to support freshness.

Although this document defines a short list of entity types, this list is extensible
to allow implementers to report on entities found in their implementation and not
covered by this specification. By using an Object Identifier (OID) for specifying entity types
and claim types, this format is inherently extensible;
implementers of this specification MAY define new custom or proprietary entity types and
place them alongside the standardized entities, or define new claim types
and place them inside standardized entities.

Verifiers SHOULD ignore and skip over
unrecognized entity or claim types and continue processing normally.
In other words, if a given Evidence would have been acceptable without the
unrecognized entities or claims, then it SHOULD still be acceptable with them.



## Claim Set and Claim Type

Each claim found in an entity is composed of the claim type and value.
Each claim describes a portion of the state of the associated entity. For example,
a platform entity could have a claim which indicates the firmware version currently running.
Another example is a key entity with a claim that reports whether the key is extractable
or not.

A value provided by a claim is to be interpreted within the context
of its entity and in relation to the claim type.

It is RECOMMENDED that a claim type be defined for a specific entity type, to reduce
confusion when it comes to interpretation of the value. In other words, a claim type SHOULD
NOT be used by multiple entity types. For example, if a concept of "revision" is applicable to a platform
and a key, the claim for one entity type (platform revision) should have a different identifier
than the one for the other entity type (key revision).

The nature of the value (boolean, integer, string, bytes) is dependent on the claim type.

This specification defines a limited set of claim types. However, the list is extensible
through the IANA registration process or private OID allocation, enabling implementers to
report additional claims not covered by this specification.

The number of claims reported within an entity, and their respective type, is
left to the implementer. For a simple device, the reported list of claims for an entity
might be fixed. However, for larger and more complex devices, the list of reported claims
should be tailored to the demands of the Presenter.

Some claims MAY be repeated within an entity while others MUST NOT. For example, for a
platform entity, there can only be one "firmware version" claim. Therefore, the associated claim
MUST NOT be repeated as it may lead to confusion. However, a claim relating to
a "ak-spki" MAY be repeated, each claim describing a different attesting key.
Therefore, the definition of a claim specifies whether or not multiple copies of that
claim are allowed within an entity claim set.

If a Verifier encounters, within a single entity, multiple copies of a claim specified as
"Multiple Allowed: No", it MUST reject the Evidence as malformed.

If a Verifier encounters, within the context of an entity, a repeated claim for a type where
multiple claims are allowed, it MUST treat each one as an independent claim and MUST NOT
consider later ones to overwrite the previous one.

# Data Model {#sec-data-model}

This section describes the data model associated with PKIX Evidence. For ease of
deployment within the target ecosystem, ASN.1 definitions and DER encoding
are used. A complete ASN.1 module is provided in {{sec-asn1-mod}}.

The top-level structures, as ASN.1 snippets, are:

~~~ asn.1
PkixEvidence ::= SEQUENCE {
    tbs                           TbsPkixEvidence,
    signatures                    SEQUENCE SIZE (0..MAX) OF SignatureBlock,
    intermediateCertificates  [0] SEQUENCE OF Certificate OPTIONAL
                                  -- As defined in RFC 5280
}

TbsPkixEvidence ::= SEQUENCE {
    version INTEGER,
    reportedEntities SEQUENCE SIZE (1..MAX) OF ReportedEntity
}

SignatureBlock ::= SEQUENCE {
   sid                  SignerIdentifier,
   signatureAlgorithm   AlgorithmIdentifier,
   signatureValue       OCTET STRING
}

SignerIdentifier ::= SEQUENCE {
   keyId                [0] EXPLICIT OCTET STRING OPTIONAL,
   subjectKeyIdentifier [1] EXPLICIT SubjectPublicKeyInfo OPTIONAL,
                            -- As defined in RFC 5280
   certificate          [2] EXPLICIT Certificate OPTIONAL
                            -- As defined in RFC 5280
}
~~~

A `PkixEvidence` message is composed of a protected section known as the To-Be-Signed (TBS) section where the Evidence
reported by the Attesting Environment is assembled. The integrity of the TBS section is ensured with one or multiple cryptographic signatures
over the content of this section. There is a provision to carry X.509 certificates supporting each signature.
The SEQUENCE OF `SignatureBlock` allows for both multi-algorithm protection and for counter-signatures
of the Evidence.
In an effort to keep the Evidence format simple, distinguishing between these two cases is left up to Verifier policy,
potentially by making use of the certificates that accompany each signature.

This design also does not prevent an attacker from removing, adding or re-ordering signatures without leaving trace.
This is discussed as part of the security considerations in {{sec-detached-sigs}}.

The TBS section is composed of a version number, to ensure future extensibility, and a sequence of reported entities.
For compliance with this specification, `TbsPkixEvidence.version` MUST be `1`.
This envelope format is not extensible; future specifications which make compatibility-breaking changes MUST increment the version number.

A `SignatureBlock` is included for each signature submitted against the TBS section. The `SignatureBlock` includes
the signature algorithm (signatureAlgorithm) and the signature itself (signatureValue). It also includes
information to identify the authority that provided the signature which is the structure `SignerIdentifier` (sid).
The signer identifier includes a combination of X.509 certificate, SubjectPublicKeyInfo (SPKI) and/or
key identifier (keyId). It is expected that a X.509 certificate will be generally used, as it provides the public key needed
to verify the signature and clearly identifies the subject that provided the signature. The SPKI and keyId are allowed
to support environments where X.509 certificates are not used.

The optional certificate list provided in `PkixEvidence.intermediateCertificates` enables the insertion
of X.509 certificates to support trusting the signatures found in signature blocks. This information is intended to provide
the certificates required by the Verifier to validate the endorsement on the certificates included
with the signatures. `intermediateCertificates` MAY include any or all intermediate CA certificates needed to build paths.
It is not required to include trust anchors. Order is not significant.

As described in {{sec-info-model}}, the `TbsPkixEvidence` is a set of entities. Each entity
is associated with a type that defines its class. The entity types are represented by object identifiers
(OIDs). The following ASN.1 definition defines the structures associated with entities:

~~~ asn.1
ReportedEntity ::= SEQUENCE {
    entityType  OBJECT IDENTIFIER,
    claims      SEQUENCE SIZE (1..MAX) OF ReportedClaim
}

id-pkix-evidence                    OBJECT IDENTIFIER ::= { 1 2 3 999 }
id-pkix-evidence-entity             OBJECT IDENTIFIER ::= { id-pkix-evidence 0 }
id-pkix-evidence-entity-transaction OBJECT IDENTIFIER ::= { id-pkix-evidence-entity 0 }
id-pkix-evidence-entity-platform    OBJECT IDENTIFIER ::= { id-pkix-evidence-entity 1 }
id-pkix-evidence-entity-key         OBJECT IDENTIFIER ::= { id-pkix-evidence-entity 2 }
~~~

In turn, entities are composed of a claim set. Each claim is composed of a type and a value.
The claim types are represented by object identifiers (OIDs). The
following ASN.1 definition defines the structures associated with claims:

~~~ asn.1
ReportedClaim ::= SEQUENCE {
    claimType      OBJECT IDENTIFIER,
    value          ClaimValue OPTIONAL
}

ClaimValue ::= CHOICE {
   bytes       [0] IMPLICIT OCTET STRING,
   utf8String  [1] IMPLICIT UTF8String,
   bool        [2] IMPLICIT BOOLEAN,
   time        [3] IMPLICIT GeneralizedTime,
   int         [4] IMPLICIT INTEGER,
   oid         [5] IMPLICIT OBJECT IDENTIFIER
}
~~~

Each claim type SHOULD be associated with a single entity type. Therefore, it is encouraged
to define claim types grouped with their respective entity type.

The type of a claim value is dictated by the claim type. When a claim type is defined, the
definition must include the type of the value, its semantic and interpretation.

The remainder of this section describes the entity types and their associated claims.


## Platform Entity

A platform entity reports information about the device where the Evidence is generated and is
composed of a set of claims that are global to the Target Environment.
It is associated with the type identifier `id-pkix-evidence-entity-platform`.

A platform entity, if provided, MUST be included only once within the reported entities. If a
Verifier encounters multiple entities of type `id-pkix-evidence-entity-platform`, it MUST
reject the Evidence as malformed.

The following table lists the claims for a platform entity (platform claims) defined
within this specification. In cases where the claim is borrowed from another specification,
the "Reference" column refers to the specification where the semantics
for the claim value can be found.
Claims defined in this specification have further details below.

| Claim Type      | Claim Value     | Reference     | Multiple? | OID                                        |
| ---             | ---             | ---           | ---       | ---                                        |
| vendor          | utf8String      | {{&SELF}}     | No        | id-pkix-evidence-claim-platform-vendor     |
| oemid           | bytes           | {{RFC9711}}   | No        | id-pkix-evidence-claim-platform-oemid      |
| hwmodel         | bytes           | {{RFC9711}}   | No        | id-pkix-evidence-claim-platform-hwmodel    |
| hwversion       | utf8String      | {{RFC9711}}   | No        | id-pkix-evidence-claim-platform-hwversion  |
| hwserial        | utf8String      | {{&SELF}}     | No        | id-pkix-evidence-claim-platform-hwserial   |
| swname          | utf8String      | {{RFC9711}}   | No        | id-pkix-evidence-claim-platform-swname     |
| swversion       | utf8String      | {{RFC9711}}   | No        | id-pkix-evidence-claim-platform-swversion  |
| dbgstat         | int             | {{RFC9711}}   | No        | id-pkix-evidence-claim-platform-debugstat  |
| uptime          | int             | {{RFC9711}}   | No        | id-pkix-evidence-claim-platform-uptime     |
| bootcount       | int             | {{RFC9711}}   | No        | id-pkix-evidence-claim-platform-bootcount  |
| fipsboot        | bool            | {{FIPS140-3}} | No        | id-pkix-evidence-claim-platform-fipsboot   |
| fipsver         | utf8String      | {{FIPS140-3}} | No        | id-pkix-evidence-claim-platform-fipsver    |
| fipslevel       | int             | {{FIPS140-3}} | No        | id-pkix-evidence-claim-platform-fipslevel  |
| fipsmodule      | utf8String      | {{FIPS140-3}} | No        | id-pkix-evidence-claim-platform-fipsmodule |

Each claim defined in the table above is described in the following sub-sections.

### vendor

A human-readable string that reports the name of the device's manufacturer. This field is for informational
purposes only and should not be used in any automated mechanism to compare the Evidence. For the purposes of comparison,
the claims `oemid` and  `hwmodel` should be used.

If the device is submitted to FIPS validation, this string should correspond to the vendor field of the submission.

### oemid, hwmodel, hwversion, swname, swversion, dbgstat, uptime, bootcount

These claims are defined in {{RFC9711}} and are reused in this specification for interoperability. Small
descriptions are offered for each to ease the reading of this specification. In case of confusion between the
description offered here and the one in {{RFC9711}}, the definition offered in the latter shall prevail.

The claim "oemid" uniquely identifies the Original Equipment Manufacturer (OEM) of the HSM. This is a
sequence of bytes and is not meant to be a human readable string.

The claim "hwmodel" differentiates models, products, and variants manufactured by a particular OEM. A model
must be unique within a given "oemid". This is a sequence of bytes and is not meant to be a human readable string.

The claim "hwversion" is a text string reporting the version of the hardware. This claim must be
interpreted along with the claim "hwmodel".

The claim "swname" is a text string reporting the name of the firmware running on the platform.

The claim "swversion" differentiates between the various revisions of a firmware offered for the platform. This
is a string that is expected to be human readable.

The claim "dbgstat" refers to the state of the debug facilities offered by the HSM. This is an integer
value describing the current state as described in {{RFC9711}}.

The claim "uptime" reports the number of seconds that have elapsed since the HSM was last booted.

The claim "bootcount" reports the number of times the HSM was booted.

### hwserial

A human-readable string that reports the serial number of the hardware module. This serial number often matches the number engraved
on the case or on an applied sticker.

### fipsboot, fipsver, fipslevel and fipsmodule

FIPS 140-3 CMVP validation places stringent requirements on the mode of operation of the device and the cryptography offered by the module, including only enabling FIPS-approved algorithms, certain requirements on entropy sources, and extensive start-up self-tests. FIPS 140-3 offers compliance levels 1 through 4 with increasingly strict requirements. Many HSMs include a configuration setting that allows the device to be taken out of FIPS mode and thus enable additional functionality or performance, and some offer configuration settings to change between compliance levels.

The boolean claim `fipsboot` indicates whether the device is currently operating in FIPS mode. When the claim value is "true", the HSM is running in compliance with the
FIPS 140 restrictions. Among other restrictions, it means that only FIPS-approved algorithms are available. If the value of this claim is "false", then the HSM is not
restricted to the behavior limited by compliance.

The textual claim `fipsver` indicates the version of the FIPS CMVP specification with which the device's operational mode is compliant. At the time of writing, the strings "FIPS 140-2" or "FIPS 140-3" SHOULD be used.

The integer claim `fipslevel` indicates the compliance level to which the device is currently operating and MUST only be 1, 2, 3, or 4. The `fipslevel` claim has no meaning if `fipsboot` is absent or `false`.

The claim `fipsmodule` is a textual field used to represent the name of the module that was submitted to CMVP for validation. The information derived by combining this claim with the vendor name shall
be sufficient to find the associated records in the CMVP database.

The FIPS status information in PKIX Evidence indicates only the mode of operation of the device and is not authoritative of its validation status.
This information is available on the NIST CMVP website or by contacting the device vendor.
As an example, some devices may have the option to enable FIPS mode in configuration even if the vendor has not submitted this model for validation. As another example, a device may be running in a mode consistent with FIPS Level 3 but the device was only validated and certified to Level 2.
A Relying Party wishing to know the validation status of the device MUST couple the device state information contained in the Evidence with a valid FIPS CMVP certificate for the device.


## Key Entity

A key entity is associated with the type `id-pkix-evidence-entity-key`. Each instance of a
key entity represents a different addressable key found in the Target Environment. There can
be multiple key entities found in Evidence, but each reported key entity MUST
describe a different key from the Target Environment. Two key entities may represent the same underlying cryptographic key
(keys with the exact same value) but they must be different portions of the Target Environment's
state.

A key entity is composed of a set of claims relating to the cryptographic key. At
minimum, a key entity MUST report the claim "identifier" to uniquely identify this cryptographic
key from any others found in the same Target Environment.

A Verifier that encounters Evidence with multiple key entities referring to the
same addressable key MUST reject the Evidence.

The following table lists the claims for a key entity defined
within this specification. The "Reference" column refers to the specification where the semantics
for the claim can be found.

| Claim Type        | Claim Value     | Reference   | Multiple? | OID                                          |
| ---               | ---             | ---         | ---       | ---                                          |
| identifier        | utf8String      | {{&SELF}}   | Yes       | id-pkix-evidence-claim-key-identifier        |
| spki              | bytes           | {{&SELF}}   | No        | id-pkix-evidence-claim-key-spki              |
| extractable       | bool            | [PKCS11]    | No        | id-pkix-evidence-claim-key-extractable       |
| sensitive         | bool            | [PKCS11]    | No        | id-pkix-evidence-claim-key-sensitive         |
| never-extractable | bool            | [PKCS11]    | No        | id-pkix-evidence-claim-key-never-extractable |
| local             | bool            | [PKCS11]    | No        | id-pkix-evidence-claim-key-local             |
| expiry            | time            | {{&SELF}}   | No        | id-pkix-evidence-claim-key-expiry            |
| purpose           | bytes           | {{&SELF}}   | No        | id-pkix-evidence-claim-key-purpose           |

An attestation key might be visible to a client of the device and be reported along with other cryptographic keys. Therefore,
it is acceptable to include a key entity providing claims about an attestation key like any other cryptographic key. An
implementation MAY reject the generation of PKIX Evidence if it relates to an attestation key.

### identifier

A human-readable string that uniquely identifies the cryptographic key. This value often contains
a UUID but could also have a numeric value expressed as text or any other textual description.

This claim MAY be repeated as some environments have more than one way to refer to a
cryptographic key.

### spki

The value of this claim contains the DER-encoded field SubjectPublicKeyInfo (see {{RFC5280}}) associated with the cryptographic
key.

### extractable, sensitive, never-extractable, local

These claims are defined as key attributes in [PKCS11] and reused in this specification for interoperability. Small
descriptions are offered for each to ease the reading of this specification. In case of confusion between the
description offered here and the one in [PKCS11], the definition offered in the latter shall prevail.

The claim "extractable" indicates that the key can be exported from the HSM. Corresponds directly to the attribute CKA_EXTRACTABLE
found in PKCS#11.

The claim "sensitive" indicates that the key cannot leave the HSM in plaintext. Corresponds directly to the attribute CKA_SENSITIVE
found in PKCS#11.

The claim "never-extractable" indicates if the key was never extractable from the HSM throughout the life of the key. Corresponds
directly to the attribute CKA_NEVER_EXTRACTABLE found in PKCS#11.

The claim "local" indicates whether the key was generated locally or imported. Corresponds directly to the attribute CKA_LOCAL
found in PKCS#11.

### expiry

Reports a time after which the key is not to be used. The device MAY enforce this policy based on its internal clock.

Note that security considerations should be taken relating to HSMs and their internal clocks. See {{sec-cons-hsm-timestamps}}.

### purpose

Reports the key capabilities associated with the subject key. Since multiple capabilities can be associated with a single key,
the value of this claim is a list of capabilities, each reported as an object identifier (OID).

The value of this claim is the DER encoding of the following structure:

~~~ asn.1

<CODE STARTS>

PkixEvidenceKeyCapabilities ::= SEQUENCE OF OBJECT IDENTIFIER

<CODE ENDS>

~~~

The following table describes the key capabilities defined in this specification. The key capabilities offered are based on key
attributes provided by PKCS#11. Each capability is assigned an object identifier (OID).

| Capability       | PKCS#11            | OID                                            |
| ---              | ---                | ---                                            |
| encrypt          | CKA_ENCRYPT        | id-pkix-evidence-key-capability-encrypt        |
| decrypt          | CKA_DECRYPT        | id-pkix-evidence-key-capability-decrypt        |
| wrap             | CKA_WRAP           | id-pkix-evidence-key-capability-wrap           |
| unwrap           | CKA_UNWRAP         | id-pkix-evidence-key-capability-unwrap         |
| sign             | CKA_SIGN           | id-pkix-evidence-key-capability-sign           |
| sign-recover     | CKA_SIGN_RECOVER   | id-pkix-evidence-key-capability-sign-recover   |
| verify           | CKA_VERIFY         | id-pkix-evidence-key-capability-verify         |
| verify-recover   | CKA_VERIFY_RECOVER | id-pkix-evidence-key-capability-verify-recover |
| derive           | CKA_DERIVE         | id-pkix-evidence-key-capability-derive         |

The use of an object identifier to report a capability allows third parties to extend this list to support
implementations that have other key capabilities.

## Transaction Entity

A transaction entity is associated with the type `id-pkix-evidence-entity-transaction`. This is
a logical entity and does not relate to any state found in the Target Environment. Instead, it
groups together claims that relate to the request of generating the Evidence.

For example, it is possible to include a "nonce" as part of the request to produce Evidence. This
nonce is repeated as part of the Evidence to prove
the freshness of the Evidence. This "nonce" is not related to any element in the Target Environment
and the transaction entity is used to gather those values into claims.

A transaction entity, if provided, MUST be included only once within the reported entities. If a
Verifier encounters multiple entities of type `id-pkix-evidence-entity-transaction`, it MUST
reject the Evidence.

The following table lists the claims for a transaction entity defined
within this specification. The "Reference" column refers to the specification where the semantics
for the claim value can be found.


| Claim Type      | Claim Value     | Reference     | Multiple? | OID                                           |
| ---             | ---             | ---           | ---       | ---                                           |
| nonce           | bytes           | {{RFC9711}}   | No        | id-pkix-evidence-claim-transaction-nonce      |
| timestamp       | time            | {{RFC9711}}   | No        | id-pkix-evidence-claim-transaction-timestamp  |
| ak-spki         | bytes           | {{&SELF}}     | Yes       | id-pkix-evidence-claim-transaction-ak-spki    |

### nonce

The claim "nonce" is used to provide "freshness" quality as to the generated Evidence. A Presenter requesting Evidence MAY provide a nonce value as part of the request. This nonce value, if specified, SHOULD be repeated in the generated Evidence as a claim within the transaction entity. Unlike EAT, only a single `transaction.nonce` is permitted to simplify verifier logic and reduce ambiguity.

This is similar to the claim "eat_nonce" as defined in {{RFC9711}}. According to that specification, this claim may be specified multiple times with
different values. However, within the scope of this specification, the "nonce" value can be specified only once within a transaction.

### timestamp

The time at which the Evidence was generated, according to the internal system clock of the Attesting Environment. This is similar to the
"iat" claim in {{RFC9711}}.

Note that security considerations should be taken relating to the evaluation of timestamps generated by HSMs. See {{sec-cons-hsm-timestamps}}.

### ak-spki

This field contains the encoded Subject Public Key Information (SPKI) for the attestation key used to sign the Evidence. The definition
and encoding for SPKIs are defined in X.509 certificates ({{RFC5280}}).

This transaction claim is used to bind the content of the Evidence with the key(s) used to sign that Evidence. The importance
of this binding is discussed in {{sec-detached-sigs}}.

## Additional Entity and Claim Types {#sec-additional-claim-types}

It is expected that HSM vendors will register additional Entity and Claim types by assigning OIDs from their own proprietary OID arcs to hold data describing additional proprietary key properties.

When new entity and claim types are used, documentation similar to the one produced in this specification SHOULD be distributed to
explain the meaning of the types and the frequency that values can be provided.

See {{sec-req-processing}}, {{sec-req-verification}} and {{sec-cons-verifier}} for handling of unrecognized custom types.

## Encoding

A PkixEvidence is to be DER encoded {{X.690}}.

If a textual representation is required, then the DER encoding MAY be subsequently encoded into Standard Base64 as defined in {{RFC4648}}.

PEM-like representations are also allowed where a MIME-compliant Base64 transformation of the DER encoding is used, provided that the
header label is "EVIDENCE". For example:

~~~
-----BEGIN EVIDENCE-----
(...)
-----END EVIDENCE-----
~~~


# Signing and Verification Procedures {#sec-verif-proc}

The `SignatureBlock.signatureValue` signs over the DER-encoded to-be-signed Evidence data
`PkixEvidence.tbs` and MUST be validated with the subject public key of the leaf
X.509 certificate contained in the `SignerIdentifier.certificate`. Verifiers MAY also use
`PkixEvidence.intermediateCertificates` to build a certification path to a trust anchor.

Note that a PkixEvidence MAY contain zero or more SignatureBlocks.
A PkixEvidence with zero SignatureBlocks is unsigned and unprotected; Verifiers MUST treat it as untrusted and MUST NOT rely on its claims.

More than one SignatureBlock MAY be used to convey a number of different semantics.
For example, the HSM's Attesting Environment might hold multiple Attestation Keys using different cryptographic
algorithms in order to provide resilience against cryptographic degradation. In this case a Verifier would be expected to validate all SignatureBlocks. Alternatively, the HSM's Attesting Service may hold multiple Attestation Keys (or multiple X.509 certificates for the same key) from multiple operational environments to which it belongs. In this case a Verifier would be expected to only validate the SignatureBlock corresponding to its own environment. Alternatively, multiple SignatureBlocks could be used to convey counter-signatures from external parties, in which case the Verifier will need to be equipped with environment-specific verification logic. Multiple of these cases, and potentially others, could be supported by a single PkixEvidence object.

Note that each SignatureBlock is a fully detached signature over the tbs content with no binding between the signed content and the SignatureBlocks meaning that a third-party can add a
counter-signature of the Evidence after the fact, or an attacker can remove a SignatureBlock without leaving any artifact. See {{sec-detached-sigs}} for further discussion.

If any `transaction.ak-spki` claims are present, the Verifier SHOULD verify that each `SignerIdentifier`’s SubjectPublicKeyInfo (or the SPKI of its `certificate`) matches at least one `ak-spki` value.


# Attestation Requests {#sec-reqs}

This section is informative in nature and implementers of this specification do not need to adhere to it. The aim of this section is
to provide a standard interface between a Presenter and an HSM producing PKIX Evidence. The authors hope that this standard interface will
yield interoperable tools between offerings from different vendors.

The interface presented in this section might be too complex for manufacturers of HSMs with limited capabilities such as smartcards
or personal ID tokens. For devices with limited capabilities, a fixed PKIX Evidence endorsed by the vendor might be installed
during manufacturing. Other approaches for constrained HSMs might be to report entities and claims that are fixed or offer limited
variations.

On the other hand, an enterprise-grade HSM with the capability to hold a large number of private keys is expected to be capable of generating
PKIX Evidence catered to the specific constraints imposed by a Verifier and without exposing extraneous information. The aim of the request
interface is to provide the means to select and report specific information in the PKIX Evidence.

This section introduces the role of "Presenter" as shown in {{fig-arch}}. The Presenter is the role that initiates the generation of PKIX
Evidence. Since HSMs are generally servers (client/server relationship) or peripherals (controller/peripheral relationship), a Presenter is
required to launch the process of creating the PKIX Evidence and capturing it to forward it to the Verifier.

~~~ aasvg
+-----------------------------+
|  Attester (HSM)             |
|                             |
|      +------------------+   |
|      | Target           |   |
|      | Environment      |   |
|      | (Entities &      |   |
|      |  values)         |   |
|      +-------+----------+   |
|              |              |
|              | Collect      |
|              | Claims(3)    |
|              v              |
|      +------------------+   |
|      | Attesting        |   |
|      | Environment      |   |
|      +--------+---------+   |
|            ^  |             |
|            |  |             |
+------------+--+-------------+
             |  |
 Attestation |  |   Evidence(4)
 Request(2)  |  |
             |  v
     +----------------+   Nonce(1)  +------------+
     |                |<------------|            |
     |    Presenter   |             |  Verifier  |
     |                |------------>|            |
     +----------------+ Evidence(5) +------------+
~~~
{: #fig-arch title="Architecture"}


The process of generating Evidence generally starts at the Verifier with the generation of a nonce. The nonce is used to ensure freshness
and this quality of the Evidence is guaranteed by the Verifier. Therefore, if a nonce is used, it must be provided to the Presenter by
the Verifier (1).

An Attestation Request (request) is assembled by the Presenter and submitted to the HSM (2). The Attesting Environment parses the request and
collects the appropriate measurements from the Target Environment.

In the previous figure, the HSM is represented as being composed of an Attesting Environment and a Target Environment. This representation is offered
as a simplified view and implementations are not required to adhere to this separation of concerns.

The Attesting Environemnt produces Evidence based on the collected information and returns it to the Presenter for distribution (4). Finally, the
Presenter forwards the Evidence to the Verifier (5).

The aim of the figure is to depict the position of the Presenter as an intermediate role between the Attester and the Verifier.
The role of "Presenter" is privileged as it controls the Evidence being generated by the Attester. However, the role is not "trusted" as
the Verifier does not have to take into account the participation of the Presenter as part of the function of appraising the Evidence.

The attestation request, shown in the figure, consists of a structure `TbsPkixEvidence` containing one `ReportedEntity` for each entity expected to
be included in the Evidence produced by the HSM.

Each instance of `ReportedEntity` included in the request is referred to as a requested entity. A requested entity contains a number of instances
of `ReportedClaim` known as requested claims. The collection of requested entities and requested claims represent the information desired
by the Presenter.

In most cases the value of a requested claim should be left unspecified by the Presenter. In the process of generating
the Evidence, the values of the desired claims are measured by the Attesting Environment within the HSM and reported accordingly. For the purpose
of creating a request, the Presenter does not specify the value of the requested claims and leaves them empty. This is possible because the definition of
the structure `ReportedClaim` specifies the element `value` as optional.

On the other hand, there are circumstances where the value of a requested claim should be provided by the Presenter. For example, when a particular
cryptographic key is to be included in the Evidence, the request must include a key entity with one of the "identifier" claim set to the value
corresponding to the desired key.

Some instances of `ReportedEntity`, such as those representing the platform or the transaction, do not need identifiers as the associated elements are
implicit in nature. Custom entity types might need selection during an attestation request and related documentation should specify how this is
achieved.

The instance of `TbsPkixEvidence` is unsigned and does not provide any means to maintain integrity when communicated from the Presenter to the HSM.
These details are left to the implementer. However, it is worth pointing out that the structure offered by `PkixEvidence` could be reused by an
implementer to provide those capabilities, as described in {{sec-cons-auth-the-presenter}}.


## Requested Claims with Specified Values

This section deals with the requested claims specified in this document where a value should be provided by a Presenter. In other words, this
section defines all requested claims that should set in the structure `ReportedClaim`. Requested claims not covered in this sub-section
should not have a specified value (left empty).

Since this section is non-normative, implementers may deviate from those recommendations.

### Key Identifiers

A Presenter may choose to select which cryptographic keys are reported as part of the PKIX Evidence. For each selected cryptographic key,
the Presenter includes a requested entity of type `id-pkix-evidence-entity-key`. Among the requested claims for this entity, the
Presenter includes one claim with the type `id-pkix-evidence-claim-key-identifier`. The value of this claim should be
set to the utf8String that represents the identifier for the specific key.

An HSM receiving an attestation request which selects a key via this approach SHOULD fail the transaction if it cannot find the cryptographic
key associated with the specified identifier.

### Nonce

A Presenter may choose to include a nonce as part of the attestation request. When producing the PKIX Evidence, the HSM repeats the
nonce that was provided as part of the request.

When providing a nonce, a Presenter includes, in the attestation request, an entity of type `id-pkix-evidence-entity-transaction`
with a claim of type `id-pkix-evidence-claim-transaction-nonce`. This claim is set with the value of the
nonce as "bytes".

It is important to note that the Presenter, as an untrusted participant, should not be generating the value for the nonce. In fact, the
nonce should be generated by the Verifier so that the freshness of the Evidence can be trusted by the Verifier.

### Custom Key Selection

An implementer might desire to select multiple cryptographic keys based on a shared attribute. A possible approach
is to include a single request entity of type `id-pkix-evidence-entity-key` including a claim with a set value. This claim
would not be related to the key identifier as this is unique to each key. A HSM supporting this scheme could select all the cryptographic
keys matching the specified claim and report them in the PKIX Evidence.

This is a departure from the base request interface, as multiple key entities are reported from a single requested entity.

More elaborate selection schemes can be envisaged where multiple requested claims specifying values would be tested against cryptographic keys.
Whether these claims are combined in a logical "and" or in a logical "or" would need to be specified by the implementer.

### Custom Transaction Entity Claims

The extensibility offered by the proposed request interface allows an implementer to add custom claims to the transaction entity in
order to influence the way that the Evidence generation is performed.

In such an approach, a new custom claim for requested entities of type "transaction" is defined. Then, a
claim of that type is included in the attestation request (as part of the transaction entity) while specifying a value. This value
is considered by the HSM while generating the PKIX Evidence.

## Reporting of Attestation Keys

There is a provision for the Attesting Environment to report the Attestation Key(s) used during the generation of the Evidence. To this end,
the transaction claim "ak-spki" is used.

A Presenter invokes this provision by submitting an attestation request with a transaction claim of type "ak-spki" with a
non-specified value (left empty).

In this case, the Attesting Environment adds a transaction claim of type "ak-spki" for each Attestation Key used to sign the Evidence. The
value of this claim is an octet string (bytes) which is the encoding of the Subject Public Key Information (SPKI) associated
with the Attestation Key. Details on SPKIs and their encoding can be found in X.509 certificates ({{RFC5280}}).

This reporting effectively binds the signature blocks to the content (see {{sec-detached-sigs}}).

## Processing an Attestation Request {#sec-req-processing}

This sub-section deals with the rules that should be considered when an Attesting Environment processes a request to generate
Evidence. This section is non-normative and implementers MAY choose to not follow these recommendations.

These recommendations apply to any attestation request schemes and are not restricted solely to the request interface proposed
here.

An Attesting Environment SHOULD fail an attestation request if it contains an unrecognized entity type. This is to ensure that all the semantics expected
by the Presenter are fully understood by the Attesting Environment.

An Attesting Environment MUST fail an attestation request if it contains a requested claim with an unrecognized type with a specified a value (not
empty). This represents a situation where the Presenter is selecting specific information that is not understood by the Attesting Environment.

An Attesting Environment SHOULD ignore unrecognized claim types in an attestation request. In this situation, the Attesting Environment SHOULD NOT include
the claim as part of the response. This guidance is to increase the likelihood of interoperability between tools of various
vendors.

An Attesting Environment MUST NOT include entities and claims in the generated Evidence if these entities and claims were
not specified as part of the request. This is to give control to the Presenter as to what information is disclosed by the Attesting Environment.

An Attesting Environment MUST fail an attestation request if the Presenter does not have the appropriate access rights to the entities or claims included
in the request.


## Verification by Presenter {#sec-req-verification}

This sub-section deals with the rules that should be considered when a Presenter receives PKIX Evidence from the Attester (the HSM)
prior to distribution. This section is non-normative and implementers MAY choose to not follow these recommendations.

These recommendations apply to any PKIX Evidence and are not restricted solely to Evidence generated from the proposed request interface.

A Presenter MUST review the Evidence produced by an Attester for fitness prior to distribution.

A Presenter MUST NOT disclose Evidence if it contains information it
cannot parse. This restriction applies to entity types and claim types. This is
to ensure that the information provided by the Attester can be evaluated by the
Presenter.

A Presenter MUST NOT disclose Evidence if it contains entities others
than the ones that were requested of the Attester. This is to ensure that only the
selected entities are exposed to the Verifier.

A Presenter MUST NOT disclose Evidence if it contains an entity with a claim
that was not requested of the Attester. This is to ensure that only the selected
information is disclosed to the Verifier.

Further privacy concerns are discussed in {{sec-cons-privacy}}.


# ASN.1 Module {#sec-asn1-mod}

~~~ asn.1

<CODE STARTS>

{::include-fold Pkix-Key-Attest-2025.asn}

<CODE ENDS>

~~~

# IANA Considerations

Please replace "{{&SELF}}" with the RFC number assigned to this document.

The following OIDs are defined in this document and will require IANA registration under the assigned arc:

* `id-pkix-evidence`
* `id-pkix-evidence-entity`
* `id-pkix-evidence-entity-transaction`
* `id-pkix-evidence-entity-platform`
* `id-pkix-evidence-entity-key`
* Claim OIDs referenced in the Platform, Key, and Transaction tables (e.g., `id-pkix-evidence-claim-platform-*`, `id-pkix-evidence-claim-key-*`, `id-pkix-evidence-claim-transaction-*`).

# Security Considerations

## Policies relating to Verifier and Relying Party {#sec-cons-verifier}

The generation of PKIX Evidence by an HSM is to provide sufficient information to
a Verifier and, ultimately, a Relying Party to appraise the Target Environment (the HSM) and make
decisions based on this appraisal.

The Appraisal Policy associated with the Verifier influences the generation of the Attestation
Results. Those results, in turn, are consumed by the Relying Party to make decisions about
the HSM, which might be based on a set of rules and policies. Therefore, the interpretation of
PKIX Evidence may greatly influence the outcome of some decisions.

A Verifier MAY reject a PKIX Evidence if it lacks the claims required per the Verifier's
appraisal policy. For example, if a Relying Party mandates a FIPS-certified device,
it SHOULD reject Evidence lacking sufficient information to verify the device's FIPS
certification status.

If a Verifier encounters a claim with an unrecognized claim type, it MAY ignore it and
treat it as extraneous information. By ignoring a claim, the Verifier may accept PKIX Evidence
that would be deemed malformed to a Verifier with different policies. However, this approach
fosters a higher likelihood of achieving interoperability.

## Simple to Implement {#sec-cons-simple}

The nature of attestation requires the Attesting Environment to be implemented in an extremely
privileged position within the HSM so that it can collect the required measurements such as
hardware registers and the user keys. For many HSM architectures, this will
place the Attesting Environment inside the "security kernel" and potentially subject to FIPS 140-3
or Common Criteria validation and change control. For both security and compliance reasons,
there is incentive for the generation and parsing logic to be simple and easy to implement
correctly. Additionally, when the data formats contained in this specification are parsed
within an HSM boundary -- that would be parsing a request entity, or parsing Evidence
produced by a different HSM -- implementers SHOULD opt for simple logic that rejects any
data that does not match the expected format, instead of attempting to be flexible.

In particular, the Attesting Environment SHOULD generate the PKIX Evidence from scratch and
avoid copying any content from the request. The Attesting Environment MUST generate PKIX Evidence
only from information and measurements that are directly observable by it.

## Detached Signatures {#sec-detached-sigs}

The construction of the Evidence structure (`PkixEvidence`) includes a collection of signature
blocks that are not explicitly bound to the content. This approach was influenced by the following
motivations:

* Multiple simultaneous signature blocks are desired to support hybrid environments where
multiple keys using different cryptographic algorithms are required to support appraisal
policies.

* Provide the ability to add counter-signatures without having to define an envelop scheme.

The concept of counter-signatures is important for environments where a number of heterogeneous
devices are deployed. In those environments, it is possible for a trusted actor, intermediary between
the Attester and the Verifier, to validate the original signature(s) and apply its own afterwards.

The ability to add signature blocks to the Evidence after the original generation by the Attester leads
to the unfortunate situation where signature blocks can also be removed without leaving any trace.
Therefore, the signature blocks can be deemed as "detachable" or "stapled".

Manipulation of the Evidence after it was generated can lead to undesired outcomes at the Verifier.

Therefore, Verifiers MUST be designed to accept Evidence based on their appraisal policies, regardless
of the presence or absence of certain signature(s). Consequently, Verifiers MUST NOT make any inferences
based on a missing signature, as the signature could have been removed in transit.

This specification provides the transaction claim "ak-spki" to effectively bind the content with
the signature blocks that were generated by the Attesting Environment. When this claim is provided, it reports
the SPKI of one of the attestation keys used by the Attesting Environment to produce the Evidence. This claim
is repeated for each of the attestation keys used by the Attesting Environment.

## Privacy {#sec-cons-privacy}

Some HSMs have the capacity of supporting cryptographic keys controlled by separate entities referred to as "tenants", and when the HSM is used in that mode
it is referred to as a multi-tenant configuration.

For example, an enterprise-grade HSM in a large multi-tenant cloud service could host TLS keys fronting multiple un-related web domains. Providing Evidence for
claims of any one of the keys would involve a Presenter that could potentially access any of the hosted keys.
In such a case, privacy violations could occur if the Presenter was to disclose information that does not relate to the subject key.

Implementers SHOULD be careful to avoid over-disclosure of information, for example by authenticating the Presenter as described in {{sec-cons-auth-the-presenter}} and only returning results for keys and portions of the Target Environment for which it is authorized.
In absence of an existing mechanism for authenticating and authorizing administrative connections to the HSM, the attestation request MAY be authenticated by embedding the TbsPkixEvidence of the request inside a PkixEvidence signed with a certificate belonging to the Presenter.

Furthermore, enterprise and cloud-services grade HSMs SHOULD support the full set of attestation request functionality described in {{sec-reqs}} so that Presenters can fine-tune the content of a PKIX Evidence such that it is appropriate for the intended Verifier.


## Authenticating and Authorizing the Presenter {#sec-cons-auth-the-presenter}

The Presenter represents a privileged role within the architecture of this specification as it gets to learn about the existence of user keys and their protection properties, as well as details of the platform.
The Presenter is in the position of deciding how much information to disclose to the Verifier, and to request a suitably redacted Evidence from the HSM.

For personal cryptographic tokens it might be appropriate for the attestation request interface to be un-authenticated. However, for enterprise and cloud-services grade HSMs the Presenter SHOULD be authenticated using the HSM's native authentication mechanism. The details are HSM-specific and are thus left up to the implementer. However, it is RECOMMENDED to implement an authorization framework similar to the following.

A Presenter SHOULD be allowed to request Evidence for any user keys which it is allowed to use.
For example, a TLS application that is correctly authenticated to the HSM in order to use its TLS keys SHOULD be able to request Evidence related to those same keys without needing to perform any additional authentication or requiring any additional roles or permissions.
HSMs that wish to allow a Presenter to request Evidence of keys which is not allowed to use, for example for the purposes of displaying HSM status information on an administrative console or UI, SHOULD have a "Attestation Requester" role or permission and SHOULD enforce the HSM's native access controls such that the Presenter can only retrieve Evidence for keys for which it has read access.

In the absence of an existing mechanism for authenticating and authorizing administrative connections to the HSM, the attestation request MAY be authenticated by embedding the `TbsPkixEvidence` of the request inside a `PkixEvidence` signed with a certificate belonging to the Presenter.

## Proof-of-Possession of User Keys

With asymmetric keys within a Public Key Infrastructure (PKI) it is common to require a key holder to prove that they are in control of the private key by using it. This is called "proof-of-possession (PoP)". This specification intentionally does not provide a mechanism for PoP of user keys and relies on the Presenter, Verifier, and Relying Party trusting the Attester to correctly report the cryptographic keys that it is holding.

It would be trivial to add a PoP Key claim that uses the attested user key to sign over, for example, the Transaction Entity. However, this approach leads to undesired consequences, as explained
below.

First, a user key intended for TLS, as an example, SHOULD only be used with the TLS protocol. Introducing a signature oracle whereby the TLS application key is used to sign PKIX Evidence could lead to cross-protocol attacks.
In this example, an attacker could submit a "nonce" value which is in fact not random but is crafted in such a way as to appear as a valid message in some other protocol context or exploit some other weakness in the signature algorithm.

Second, the Presenter who has connected to the HSM to request PKIX Evidence may have permissions to list the requested application keys but not permission to use them, as in the case where the Presenter is an administrative UI displaying HSM status information to a system's administrator or auditor.

Requiring the Attesting Environment to use the reported application keys to generate Evidence could, in some architectures, require the Attesting Environment to resolve complex access control logic and handle complex error conditions, which violates the "simple to implement" design principle outlined in {{sec-cons-simple}}. More discussions on authenticating the Presenter can be found in {{sec-cons-auth-the-presenter}}.

## Timestamps and HSMs {#sec-cons-hsm-timestamps}

It is common for HSMs to have an inaccurate system clock. Most clocks have a natural drift and must be corrected periodically. HSMs, like any other devices,
are subject to these issues.

There are many situations where HSMs can not naturally correct their internal system clocks. For example, consider a HSM hosting a trust anchor and usually kept offline
and booted up infrequently in a network without a reliable time management service. Another example is a smart card which boots up only when held against an NFC reader.

When a timestamp generated from a HSM is evaluated, the expected behavior of the system clock SHOULD be considered.

More specifically, the timestamp SHOULD NOT be relied on for establishing the freshness of the Evidence generated by a HSM. Instead, Verifiers SHOULD rely on other provisions
such as the "nonce" claim of the "transaction" entity, introduced in this specification.

Furthermore, the internal system clock of HSMs SHOULD NOT be relied on to enforce expiration policies.
--- back

# Samples

A reference implementation of this specification can be found at https://github.com/ietf-rats-wg/key-attestation

It produces the following sample Evidence:

~~~
{::include-fold sampledata/idea3/sample1.txt}
~~~

# Acknowledgements

This specification is the work of a design team created by the chairs
of the RATS working group. This specification has been developed
based on discussions in that design team and also with great amounts of
input taken from discussions on the RATS mailing list.

We would like to thank Jeff Andersen for the review comments.

We would like to thank Dave Thaler for his guidance.

