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
keyword: Internet-Draft
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
    organization: University of Applied Sciences Bonn-Rhein-Sieg
    abbrev: H-BRS
    country: Germany
    email: Hannes.Tschofenig@gmx.net

  - name: Henk Birkholz
    organization: Fraunhofer SIT
    email: henk.birkholz@ietf.contact

  - name: Monty Wiseman
    org:
    country: USA
    email: montywiseman32@gmail.com

  - name: Ned Smith
    organization: Intel Corporation
    country: USA
    email: ned.smith@intel.com

normative:
  RFC2119:
  RFC9334:
  RFC5280:
  RFC9711:
  X.680:
     title: "Information technology -- Abstract Syntax Notation One (ASN.1): Specification of basic notation"
     author:
        org: ITU-T
        date: false
     target: https://www.itu.int/rec/T-REC-X.680
  X.690:
      title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
      date: November 2015
      author:
        org: ITU-T
      seriesinfo:
        ISO/IEC: 8825-1:2015
  PKCS11:
    title: "PKCS #11 Specification Version 3.1"
    author:
      name: Dieter Bong, Tony Cox
      org: OASIS PKCS 11 TC
      date: 11 August 2022
    target: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/cs01/pkcs11-spec-v3.1-cs01.html
  FIPS.140-3:
    -: fips
    title: SECURITY REQUIREMENTS FOR CRYPTOGRAPHIC MODULES
    author:
      org: NIST - Information Technology Laboratory
    seriesinfo:
      FIPS: 140-3
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf

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
    org: National Security Agency
    target: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
  codesigningbrsv3.8:
    title: "Baseline Requirements for the Issuance and Management of Publicly‐Trusted Code Signing Certificates Version 3.8.0"
    org: CA/Browser Forum
    target: https://cabforum.org/working-groups/code-signing/documents/

entity:
  SELF: "RFCthis"

--- abstract

This document specifies a vendor-agnostic format for evidence produced and verified within a PKIX context.
The evidence produced this way includes claims collected about a cryptographic module
and elements found within it such as cryptographic keys.

One scenario envisaged is that the state information about the cryptographic module can be securely presented
to a remote operator or auditor in a vendor-agnostic verifiable format.
A more complex scenario would be to submit this evidence to a Certification Authority to aid in determining
whether the storage properties of this key meet the requirements of a given certificate profile.

This specification also offers a format for requesting a cryptographic module to produce evidence tailored for expected use.

--- middle

# Introduction

This specification defines a format to transmit Evidence from an Attester to a Verifier within a PKIX
environment. This environment refers to the components generally used to support PKI applications
such as Certification Authorities and their clients, or more generally that rely upon X.509 certificates.
As outlined in {{sec-terminology}}, this specification uses a necessary mixture of RATS and PKI terminology
in order to map concepts between the two domains.

Within this specification, the concepts found in the Remote Attestation Procedures (RATS {{!RFC9334}}) are
mapped to the PKIX environment. There are many other specifications that are based on the RATS architecture
which offer formats to carry evidence. This specification deals with peculiar aspects of the PKIX environment
which make the existing evidence formats inappropriate:

* ASN.1 is the preferred encoding format in this environment. X.509 certificates ({{!RFC5280}}) are used
widely within this environment and the majority of tools are designed to support ASN.1. There are
many specialized devices (Hardware Security Modules) that are inflexible in adopting other formats because
of internal constraints or validation difficulties. This specification defines the format in ASN.1 to ease the
adoption within the community.

* The claims within the Evidence are about internal elements such as "platforms" and "keys" which are not
necessarily distinct from the Attesting Environment. Therefore, although the concept
of "measurement" is present within the PKIX environment, it is not always clear that one attesting environment
is measuring another distinct target environment the way it is envisioned in the RATS Architecture.
Therefore, the emphasis and structure of this specifications is adjusted accordingly.
Specifically, this specification assumes that the Attesting Environment and the Target Environment,
as outlined in {{!RFC9334}}, are the same. This might not be the case for all devices encountered, but is
sufficient for the proposed specification.

Another important influence on the development of this specification is that the envisaged Target Environments
are quite large and that only a portion of the total addressable state shall be divulged as part of evidence.
Therefore, a scheme based on "entities" is used to carved the portion of the Target Environment to be measured
and reported. To this end, the concepts of "claims" and "measurements" are folded into "entities" and "attributes"
(see {sec-info-model}).

This specification also aims at providing an extensible framework to encode within Evidence claims other than
the one proposed in this document. This allows implementations to introduce new claims and their associated
semantics to the Evidence produced.


# Use Cases

This section covers use cases that motivated the development of this specification.


## Remote audit of a Hardware Security Module (HSM)

There are situations where it is necessary to verify the current running state of an HSM as part of operational or
auditing procedures. For example, there are devices that are certified to work in an environment only if certain
versions of the firmware are loaded or only if application keys are protected in with a certain set of protection policies.

The Evidence format offered by this specification allows a platform to report its firmware level along with
other collected claims necessary in critical deployments.


## Key import and HSM clustering

Consider that an HSM is being added to a logical HSM cluster. Part of the onboarding process could involve
the newly-added HSM providing proof of its running state, for example that it is a genuine device from
the same manufacturer as the existing clustered HSMs, firmware patch level, FIPS mode, etc.
It could also be required to provide attestation of any system-level keys required for secure establishment
of cluster communication. In this scenario, the Verifier and Relying Party will be the other HSMs in the cluster
deciding whether or not to admit the new HSM.

A related scenario is when performing a key export-import across HSMs.
If the key is being imported with certain properties, for example an environment running in FIPS mode at
FIPS Level 3, and the key is set to certain protection properties such as Non-Exportable and Dual-Control,
then the HSM might wish to verify that the key was previously stored under the same properties.
This specification provides a way to do this across HSM vendors.

These scenarios motivate the design requirements to have an ASN.1 based Evidence format and a data model that
more closely matches typical HSM architecture since in both scenarios
an HSM is acting as Verifier and Relying Party.


## Attesting subject of a certificate issuance

Prior to a Certification Authority (CA) issuing a certificate on behalf of a subject, a number of procedures
are required to verify that the subject of the certificate is associated with the key that is certified.
In some cases, such as issuing a code signing certificate [CNSA2.0], [codesigningbrsv3.8], a CA must ensure that
the subject key is located in a Hardware Security Module (HSM).

The Evidence format offered by this specification is designed to carry the information necessary for a CA to
assess the location of the subject key along a number of commonly-required attributes. More specifically, a CA could
determine which HSM was used to generate the subject key, whether this device adheres
to certain jurisdiction policies (such as FIPS mode) and the constraints applied to the key (such as whether is it extractable).

For relatively simple HSM devices, storage properties such as "extractable" may always be true for all keys
since the devices are not capable of key export and so the attestation could be essentially a hard-coded template asserting these
immutable attributes. However, more complex HSM devices require a more complex evidence format that encompasses the
mutability of these attributes.
Also, the client requesting the key attestation might wish to scope-down the content of the key attestation as
the HSM contains many keys and only a certain subset are relevant for attesting a given transaction, or only
certain claims are relevant.
Lack of ability to scope-down the key attestation contents could, in some scenarios, constitute a privacy violation.
This motivates the design choice for a key attestation request mechanism.
The same objective could have been accomplished via a selective disclosure mechanism. However, since a request
is necessary to transmit the nonce to the HSM, a standardized request format fits the use case better
and is generally simpler.



# Terminology {#sec-terminology}

This specification uses a necessary mixture of RATS and PKI terminology
in order to map concepts between the two domains.

The reader is assumed to be familiar with the vocabulary and concepts
defined in the RATS architecture ({{!RFC9334}}) such as Attester,
Relying Party, Verifier.

The reader is assumed to be familiar with common vocabulary and concepts
defined in {{!RFC5280}} such as certificate, signature, attribute, verifier.

In order to avoid confusion, this document generally
capitalizes RATS terms such as Attester, Relying Party, and Claim.
Therefore, for example, a "Verifier"
should be assumed to be an entity that checks the validity of Evidence as per {{!RFC9334}},
whereas a "verifier" could be a more general reference to a PKI entity that checks
the validity of an X.509 certificate or other digital signature as per {{!RFC5280}}.

The following terms are used in this document:

{: vspace="0"}

Attestation Key (AK):
: Cryptographic key controlled solely by the Attester and used only for the purpose
of producing Evidence. In other words, it is used to digitally sign the claims collected by
the Attester.

Attestation Service (AttS):
: A logical module within the HSM that is responsible for generating Evidence compatible with the
format outlined in this specification. It collects claims from the platform and uses the Attestation
Key to digitally sign the collection.

Attester :
: The term Attester respects the definition offered in {{!RFC9334}}. In this specification, it
is also interchangeable with "platform" or "HSM".

Evidence :
: The term Evidence respects the definition offered in {{!RFC9334}}. In this specification, it
refers to claims, encoded according to the format defined within this document, and signed using
the Attestation Key.

Hardware Security Module (HSM):
: A physical computing device that safeguards and manages secrets, such as cryptographic keys,
and performs cryptographic operations based on those secrets.
This specification takes a broad definition of what counts as an HSM to include smartcards,
USB tokens, TPMs, cryptographic co-processors (PCI cards) and "enterprise-grade" or "cloud-service grade" HSMs
(possibly rack mounted). In this specification, it is interchangeable with "platform" or "Attester".

Key Attestation:
: Process of producing Evidence containing claims pertaining to user keys found within an HSM. In
general, the claims includes enough information about a user key and its hosting platform to allow
a Relying Party to make judicious decisions about the key, such as whether to issue a certificate for the key.

Platform:
: The module or device that embodies the Attester. In this specification, it is interchangeable with
"Attester" or "HSM".

Platform Attestation:
: Evidence containing claims pertaining to attributes associated with the platform itself. In general, the claims include
enough information about the platform to allow a Relying Party to make judicious decisions about the
platform, such as those carried out during audit reviews.

Presenter
: Role that facilitates communication between the Attester and the Verifier. The
  Presenter initiates the operation of generating evidence at the Attester and
  passes the generated evidence to the Verifier. In the case of HSMs, the Presenter
  is responsible of selecting the claims that are part of the generated evidence.

Trust Anchor:
: As defined in {{RFC6024}} and {{RFC9019}}, a Trust Anchor
"represents an authoritative entity via a public key and
associated data. The public key is used to verify digital
signatures, and the associated data is used to constrain the types
of information for which the trust anchor is authoritative." The
Trust Anchor may be a certificate, a raw public key, or other
structure, as appropriate.

Trusted Platform Module (TPM):
A tamper-resistance processor generally located on a computer's motherboard used to enhance attestation
functions for the hosting platform. TPMs are very specialized Hardware Security Modules and generally use
other protocols (than the one presented in this specification) to transmit evidence.

User Key:
: A user key consists of a key hosted by an HSM (the platform) and intended to be used by a client
of the HSM. Other terms used for a user key are "application key", "client key" or "operational key".
The access and operations on a user key is controlled by the HSM.


{::boilerplate bcp14-tagged}

## Attestation Key Certificate Chain {#sec-ak-chain}

The data format in this specification represents PKIX evidence and
requires third-party endorsement in order to establish trust. Part of this
endorsement is a trust anchor that chains to the HSM's attestation key (AK)
which signs the evidence. In practice the trust anchor will usually be a
manufacturing CA belonging to the device vendor which proves
that the device is genuine and not counterfeit. The trust anchor can also belong
to the device operator as would be the case when the AK certificate is replaced
as part of onboarding the device into a new operational network.

The AK certificate that signs the evidence MUST have the Extended Key Usage
`id-kp-attest` defined in \[TODO-submit-2-pager-to-lamps\].

Note that the data format specified in {{sec-data-model}} allows for zero, one, or multiple
'SignatureBlock's, so a single evidence statement could be un-protected, or could be endorsed by multiple
AK chains leading to different trust anchors. See {{sec-verif-proc}} for a discussion of handling multiple SignatureBlocks.


# Information Model {#sec-info-model}

The PKIX Evidence format is composed of two main sections:

* A claim description section which describes the information transmitted as Evidence.

* A signature section where one or more digital signatures are offered to prove the origin of the
  claims and maintain their integrity.

The details of the signature section is left to the data model. The remainder of this section
deals with the way the information is organized to form the claims.

The claims are organized into a set of entities to help with the organization and comprehension
of the information. Entities are elements observed in the Target Environment by the Attester.
Each entity, in turn, is associated with a set of attributes.

Therefore, the Claim description section is a set of entities and each entity is composed
of a set of attributes.

## Entity

An entity is a logical construct that refers to a portion of the Target Environment's state. It is
addressable via an identifier such as a UUID or a handle (as expressed in [PKCS11]). In general, an
entity refers to a component recognized by users of the HSM, such as a key or the platform itself.

An entity is composed of a type, the entity type, and a set of attributes. The entity type
describes the class of the entity while its attributes defines its state.

An entity MUST be reported at most once in a claim description. The claim description can
have multiple entities of the same type (for example reporting multiple keys), but each
entity MUST be relating to different portions of the Target Environment.

It is possible for two entities to be quite similar such as in a situation where a key is imported
twice in a HSM. In this case, the two related entities could have similar attributes. However, they
are treated as different entities as they are addressed differently.

The number of entities reported in a claim description, and their respective type, is
left to the implementer. For a simple device where there is only one key, the list of
reported entities could be fixed. For larger and more complex devices, the list of
reported entities should be tailored to the demands of the Presenter.

In particular, note that the nonce attribute contained with the Transaction entity is optional,
and therefore it is possible that an extremely simple device that holds one static key
could have its key attestation object generated at manufacture time and injected
statically into the device and act as a kind of certificate, instead of
being generated on-demand. This model would essentially
off-board the Target Environment to be part of the manufacturing infrastructure.


## Entity Type

An entity is defined by its type. This specification defines three entity types:

* Platform : This entity holds attributes relating to the state of the platform, or device,
  where the Attester is located. Entities of this type hold attributes that are global
  in nature within the Target Environment.

* Key : The entities of this type represent a cryptographic key protected within the
  Target Environment and hold attributes relating to that key.

* Transaction : This entity is logical in nature since it is associated with attributes
  that are not found in the Target Environment. The attributes found in this entity relate
  to the current request for Evidence such as a nonce to support freshness.

Although this document defines a short list of entity types, this list is extensible
to allow implementers to report on entities found in their implementation and not
covered by this specification. By using an Object Identifier (OID) for identifying both entity types
and the attribute types that they contain, this format is inherently extensible;
implementers of this specification MAY define new custom or proprietary entity types and
place them alongside the standardized entities, or define new attribute types
and place them inside standardized entities.

Verifiers SHOULD ignore and skip over
unrecognized entity or attribute types and continue processing normally.
In other words, if a given Evidence would have been acceptable without the
unrecognized entity or attribute, then it SHOULD still be acceptable.



## Attribute and Attribute Type

Each attribute found in an entity is composed of the attribute type and value.
Each attribute describes a portion of the state of the associated entity. For example,
a platform entity could have an attribute which indicates the firmware version currently running.
Another example is a key entity with an attribute that reports whether the key is extractable
or not.

A value provided by an attribute is to be interpreted within the context
of its entity and in relation to the attribute type.

It is RECOMMENDED that an attribute type be defined for a specific entity type, to reduce
confusion when it comes to interpretation of the value. In other words, an attribute type SHOULD
NOT be used by multiple entity types. For example, if a concept of "revision" is applicable to a platform
and a key, the attribute for one entity type (platform revision) should have a different identifier
than the one for the other entity type (key revision).

The nature of the value (boolean, integer, string, bytes) is dependent on the attribute type.

This specification defines a limited set of attribute types. However, the list is extensible
through the IANA registration process or private OID allocation, enabling implementers to
report additional attributes not covered by this specification.

The number of attributes reported within an entity, and their respective type, is
left to the implementer. For a simple device, the reported list of attributes for an entity
might be fixed. However, larger and more complex devices, the list of reported attributes
should be tailored to the demands of the Presenter.

Some attributes MAY be repeated within an entity while others MUST NOT. For example, for a
platform entity, there can only be one "firmware version" attribute. Therefore, the associated attribute
MUST NOT be repeated as it may lead to confusion. However, an attribute relating to
a "loaded module" MAY be repeated, each attribute describing a different loaded module.
Therefore, the definition of an attribute specifies whether or not multiple copies of that
attribute are allowed.

If a Verifier encounters, within a single entity, multiple copies of an attribute specified as
"Multiple Allowed: No", it MUST reject the evidence as malformed.

If a Verifier encounters, within the context of an entity, a repeated attribute for a type where
multiple attributes are allowed, it MUST treat each one as an independent attribute and MUST NOT
consider later ones to overwrite or extend the previous one.

# Data Model {#sec-data-model}

This section describes the data model associated with PKIX Evidence. For ease of
deployment within the target ecosystem, ASN.1 definitions and DER encoding
are used. A complete ASN.1 module is provided in {{sec-asn1-mod}}.

The top-level structures are:

~~~asn.1
PkixEvidence ::= SEQUENCE {
    tbs                           TbsPkixEvidence,
    signatures                    SEQUENCE SIZE (0..MAX) of SignatureBlock,
    intermediateCertificates  [0] IMPLICIT SEQUENCE of Certificate OPTIONAL
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

A PkixEvidence message is composed of a protected section known as the To-Be-Signed (TBS) section where the evidence
reported by the HSM is assembled. The integrity of the TBS section is ensured with one or multiple cryptographic signatures
over the content of this section. There is a provision to carry X.509 certificates supporting each signature.
The SEQUENCE OF SignatureBlock allows for both multi-algorithm protection and for counter-signatures
of the evidence.
In an effort to keep the evidence format simple, distinguishing between these two cases is left up to Verifier policy,
potentially by making use of the certificates that accompany each signature.
This design also does not prevent an attacker from removing, adding or re-ordering signatures without leaving evidence.
Again, this is left up to Verifier and its policy to enforce the expected number of algorithms or signatures.
Consequently, Verifiers MUST NOT make any inferences about the lack of a signature. For example, enumerating
counter-signatures on an Evidence MUST NOT be considered to be a complete list of HSMs in a given cluster.
Similarly, the presence and order of counter-signatures MUST NOT be taken as proof of the path that the evidence traversed
over the network.

The TBS section is composed of a version number, to ensure future extensibility, and a sequence of reported entities.
For compliance with this specification, `TbsPkixEvidence.version` MUST be `1`.
This envelope format is not extensible; future specifications which make compatibility-breaking changes MUST increment the version number.

A `SignatureBlock` is included for each signature submitted against the TBS section. The SignatureBlock includes
the signature algorithm (signatureAlgorithm) and the signature itself (signatureValue). It also includes
information to identify the authority that provided the signature which is the structure `SignerIdentifier` (sid).
The signer identifier includes a combination of X.509 certificate, Subject Public Key Identifier (SPKI) and/or
key identifier (keyId). It is expected that a X.509 certificate will be generally used, as it provides the public key needed
to verify the signature and clearly identifies the subject that provided the signature. The SPKI and keyId are allowed
to support environments where X.509 certificates are not used.

The optional certificates provided in `PkixEvidence.intermediateCertificates` enables the insertion
of X.509 certificates to support trusting the signatures. This information is intended to provide
the certificates required by the Verifier to verified the endorsement on the certificates included
with the signatures.

As described in the {{sec-info-model}} section, the `TbsPkixEvidence` is a set of entities. Each entity
is associated with a type that defines its class. The entity types are represented by object identifiers
(OIDs). The following ASN.1 definition defines the structures associated with entities:

~~~asn.1
ReportedEntity ::= SEQUENCE {
    entityType         OBJECT IDENTIFIER,
    reportedAttributes SEQUENCE SIZE (1..MAX) OF ReportedAttribute
}

id-pkix-evidence                    OBJECT IDENTIFIER ::= { 1 2 3 999 }
id-pkix-evidence-entity-type        OBJECT IDENTIFIER ::= { id-pkix-evidence 0 }
id-pkix-evidence-entity-transaction OBJECT IDENTIFIER ::= { id-pkix-evidence-entity-type 0 }
id-pkix-evidence-entity-platform    OBJECT IDENTIFIER ::= { id-pkix-evidence-entity-type 1 }
id-pkix-evidence-entity-key         OBJECT IDENTIFIER ::= { id-pkix-evidence-entity-type 2 }
~~~

In turn, entities are composed of attributes. Each attribute is composed of a type and a value.
The attribute types are represented by object identifiers (OIDs). The
following ASN.1 definition defines the structures associated with attributes:

~~~asn.1
ReportedAttribute ::= SEQUENCE {
    attributeType      OBJECT IDENTIFIER,
    value              OPTIONAL AttributeValue
}

AttributeValue :== CHOICE {
   bytes       [0] IMPLICIT OCTET STRING
   utf8String  [1] IMPLICIT UTF8String,
   bool        [2] IMPLICIT BOOLEAN,
   time        [3] IMPLICIT GeneralizedTime,
   int         [4] IMPLICIT INTEGER,
   oid         [5] IMPLICIT OBJECT IDENTIFIER
}
~~~

The attributes associated with an entity are dependent on the type of entity. Therefore, it is encouraged
to define attribute types grouped with their respective entity type.

The type of an attribute value is dictated by the attribute type. When an attribute type is defined, the
definition must include the type of the value, its semantic and interpretation.

The remainder of this section describes the entity types and their associated attributes.


## Platform Entity

A platform entity is associated with the type identifier `id-pkix-evidence-entity-platform`. It is composed
of a set of attributes that are global to the Target Environment.

A platform entity, if provided, MUST be included only once within the reported entities. If a
Verifier encounters multiple entities of type `id-pkix-evidence-entity-platform`, it MUST
reject the Evidence as malformed.

The following table lists the attributes for a platform entity (platform attributes) defined
within this specification. In cases where the attribute is borrowed from another specification,
the "Reference" column refers to the specification where the semantics
for the attribute value can be found.
Attributes defined in this specification have further details below.

| Attribute       | AttributeValue  | Reference    | Multiple? | OID                                           |
| ---             | ---             | ---          | ---       | ---                                           |
| vendor          | utf8String      | {{&SELF}}    | No        | id-pkix-evidence-attribute-platform-vendor    |
| oemid           | bytes           | {{!RFC9711}} | No        | id-pkix-evidence-attribute-platform-oemid     |
| hwmodel         | utf8String      | {{!RFC9711}} | No        | id-pkix-evidence-attribute-platform-model     |
| hwserial        | utf8String      | {{&SELF}}    | No        | id-pkix-evidence-attribute-platform-hwserial  |
| swversion       | utf8String      | {{!RFC9711}} | No        | id-pkix-evidence-attribute-platform-swversion |
| dbgstat         | int             | {{!RFC9711}} | No        | id-pkix-evidence-attribute-platform-debugstat |
| uptime          | int             | {{!RFC9711}} | No        | id-pkix-evidence-attribute-platform-uptime    |
| bootcount       | int             | {{!RFC9711}} | No        | id-pkix-evidence-attribute-platform-bootcount |
| usermods        | utf8String      | {{&SELF}}    | Yes       | id-pkix-evidence-attribute-platform-usermods  |
| fipsboot        | bool            | {{-fips}}    | No        | id-pkix-evidence-attribute-platform-fipsboot  |
| fipsver         | utf8String      | {{-fips}}    | No        | id-pkix-evidence-attribute-platform-fipsver   |
| fipslevel       | int             | {{-fips}}    | No        | id-pkix-evidence-attribute-platform-fipslevel |
| envdesc         | utf8String      | {{&SELF}}    | Yes       | id-pkix-evidence-attribute-platform-envdesc   |

TODO: find the actual reference for "FIPS Mode" -- FIPS 140-3 does not define it (at least not the 11 page useless version of 140-3 that I found).

Each attribute defined in the table above is described in the following sub-sections.

### vendor

A human-readable string that reports the name of the device's manufacturer.

### oemid, hwmodel, swversion, dbgstat, uptime, bootcount

These attributes are defined in {{!RFC9711}} and reused in this specification for interoperability. Small
descriptions are offered for each to ease the reading of this specification. In case of confusion between the
description offered here and the one in {{!RFC9711}}, the definition offered in the latter shall prevail.

The attribute "oemid" uniquely identifies the Original Equipment Manufacturer (OEM) of the HSM. This is a
sequence of bytes and is not meant to be a human readable string.

The attribute "hwmodel" differentiates models, products, and variants manufactured by a particular OEM. A model
must be unique within a given "oemid". This is a sequence of bytes and is not meant to be a human readable string.

EDNOTE: JPF: "hwmodel" in EAT is not human readable. We have "vendor" that duplicates in human readable for "oemid".
Should we duplicate "hwmodel" in a human readable form? Should we define it here for ourselves?

The attribute "swversion" differentiates between the various revisions of a firmware offered for the HSM. This
is a string that is expected to be human readable.

EDNOTE: JPF: In EAT, "swversion" requires "swname". Should we add "swname" or disassociate from the EAT definition?

The attribute "dbgstat" refers to the state of the debug facilities offered by the HSM. This is an integer
value describing the current state as described in {{!RFC9711}}.

The attribute "uptime" reports the number of seconds that have elapsed since the HSM was last booted.

The attribute "bootcount" reported the number of times the HSM was booted.

### hwserial

A human-readable string that reports the serial number of the hardware module. This serial number often matches the number engraved
on the case or on an applied sticker.

### usermods

Most HSMs have some concept of trusted execution environment where user software modules can be loaded inside the HSM to run with some level of privileged access to the application keys. This attribute lists user modules currently loaded onto the HSM in a human readable format, preferably JSON.

EDNOTE: JPF if JSON, why have multiple attributes.

### fipsboot, fipsver and fipslevel

FIPS 140-3 CMVP validation places stringent requirements on the mode of operation of the device and the cryptography offered by the module, including only enabling FIPS-approved algorithms, certain requirements on entropy sources, and extensive start-up self-tests. FIPS 140-3 offers compliance levels 1 through 4 with increasingly strict requirements. Many HSMs include a configuration setting that allows the device to be taken out of FIPS mode and thus enable additional functionality or performance, and some offer configuration settings to change between compliance levels.

The boolean attribute `fipsboot` indicates whether the device is currently operating in FIPS mode. When the attribute value is "true", the HSM is running in compliance with the
FIPS 140 restrictions. Among other restrictions, it means that only FIPS-approved algorithms are available. If the value of this attribute is "false", then the HSM is not
restricted to the behavior limited by compliance.

The UTF8String attribute `fipsver` indicates the version of the FIPS CMVP specification with which the device's operational mode is compliant. At the time of writing, the strings "FIPS 140-2" or "FIPS 140-3" SHOULD be used.

The integer attribute `fipslevel` indicates the compliance level to which the device is currently operating and MUST only be 1, 2, 3, or 4. The `fipslevel` attribute has no meaning if `fipsboot` is absent or `false`.

The FIPS status information in PKIX Evidence indicates only the mode of operation of the device and is not authoritative of its validation status.
This information is available on the NIST CMVP website or by contacting the device vendor.
As an example, some devices may have the option to enable FIPS mode in configuration even if the vendor has not submitted this model for validation. As another example, a device may be running in a mode consistent with FIPS Level 3 but the device was only validated and certified to Level 2.
A Relying Party wishing to know the validation status of the device MUST couple the device state information contained in the Evidence with a valid FIPS CMVP certificate for the device.

### envdesc

Further description of the environment beyond hwvendor, hwmodel, hwserial, swversion; for example if there is a need to describe multiple logical partitions within the same device. Contents could be a human-readable description or other identifiers.


## Key Entity

A key entity is associated with the type `id-pkix-evidence-entity-key`. Each instance of a
key entity represents a different addressable key found in the Target Environment. There can
be multiple key entities found in a claim description, but each reported key entity MUST
describe a different key. Two key entities may represent the same underlying cryptographic key
(keys with the exact same value) but they must be different portion of the Target Environment's
state.

A key entity is composed of a set of attributes relating to the cryptographic key. At
minimum, a key entity MUST report the attribute "identifier" to uniquely identify this cryptographic
key from any others found in the same Target Environment.

A Verifier that encounters a claim description with multiple key entities referring to the
same addressable key MUST reject the Evidence.

The following table lists the attributes for a key entity defined
within this specification. The "Reference" column refers to the specification where the semantics
for the attribute value can be found.

| Attribute         | AttributeValue  | Reference   | Multiple? | OID                                              |
| ---               | ---             | ---         | ---       | ---                                              |
| identifier        | utf8String      | {{&SELF}}   | Yes       | id-pkix-evidence-attribute-key-identifier        |
| spki              | bytes           | {{&SELF}}   | No        | id-pkix-evidence-attribute-key-spki              |
| purpose           | bytes           | [PKCS11]    | No        | id-pkix-evidence-attribute-key-purpose           |
| extractable       | bool            | [PKCS11]    | No        | id-pkix-evidence-attribute-key-extractable       |
| sensitive         | bool            | [PKCS11]    | No        | id-pkix-evidence-attribute-key-sensitive         |
| never-extractable | bool            | [PKCS11]    | No        | id-pkix-evidence-attribute-key-never-extractable |
| local             | bool            | [PKCS11]    | No        | id-pkix-evidence-attribute-key-local             |
| expiry            | time            | {{&SELF}}   | No        | id-pkix-evidence-attribute-key-expiry            |

An attestation key might be visible to a client of the device and be reported along with other cryptographic keys. Therefore,
it is acceptable to include a key entity providing claims about an attestation key like any other cryptographic key. An
implementation MAY reject the generation of PKIX Evidence if it relates to an attestation key.

### identifier

A human-readable string that uniquely identifies the cryptographic key. This value often contains
a UUID but could also have a numeric value expressed as text or any other textual description.

This attribute MAY be repeated as some environments have more than one way to refer to a
cryptographic key.

### spki

The value of this attribute contains the DER-encoded field SubjectPublicKeyInfo (see {{!RFC5280}}) associated with the cryptographic
key.

### purpose, extractable, sensitive, never-extractable, local

These attributes are defined in [PKCS11] and reused in this specification for interoperability. Small
descriptions are offered for each to ease the reading of this specification. In case of confusion between the
description offered here and the one in [PKCS11], the definition offered in the latter shall prevail.

The attribute "purpose" defines the intended usage for the key.

EDNOTE: JPF: I do not see "purpose" as part of PKCS#11

The attribute "extractable" indicates that the key can be exported from the HSM. Corresponds directly to the attribute CKA_EXTRACTABLE
found in PKCS#11.

The attribute "sensitive" indicates that the key cannot leave the HSM in plaintext. Corresponds directly to the attribute CKA_SENSITIVE
found in PKCS#11.

The attribute "never-extractable" indicates if the key was never extractable from the HSM throughout the life of the key. Corresponds
directly to the attribute CKA_NEVER_EXTRACTABLE found in PKCS#11.

The attribute "local" indicates whether the key was generated locally or imported.. Corresponds directly to the attribute CKA_LOCAL
found in PKCS#11.

### expiry

Reports a time after which the key is not to be used. The device MAY enforce this policy based on its internal clock.

## Transaction Entity

A transaction entity is associated with the type `id-pkix-evidence-entity-transaction`. This is
a logical entity and does not relate to an element found in the Target Environment. Instead, it
groups together attributes that relate to the request of generating the Evidence.

For example, it is possible to include a "nonce" as part of the request to produce Evidence. This
nonce is repeated as part of the Evidence, within the portion protected for integrity, to prove
the freshness of the claims. This "nonce" is not related to any element in the Target Environment
and the transaction entity is used to gather those values into attributes.

A transaction entity, if provided, MUST be included only once within the reported entities. If a
Verifier encounters multiple entities of type `id-pkix-evidence-entity-transaction`, it MUST
reject the Evidence.

The following table lists the attributes for a transaction entity defined
within this specification. The "Reference" column refers to the specification where the semantics
for the attribute value can be found.

A default and vendor-agnostic set of transaction entity attributes is defined in this section.

These attribute types MAY be contained within a transaction entity; i.e. an entity identified by `id-pkix-evidence-entity-transaction`.

| Attribute       | AttributeValue  | Reference    | Multiple? | OID                                               |
| ---             | ---             | ---          | ---       | ---                                               |
| nonce           | bytes           | {{!RFC9711}} | No        | id-pkix-evidence-attribute-transaction-nonce      |
| timestamp       | time            | {{!RFC9711}} | No        | id-pkix-evidence-attribute-transaction-timestamp  |

### nonce

The attribute "nonce" is used to provide "freshness" quality as to the claims provided in the PkixEvidence message. A Presenter requesting a PkixEvidence message MAY provide a nonce value as part of the request. This nonce value, if provided, SHOULD be repeated as an attribute within the transaction entity.

This is similar to the attribute "eat_nonce" as defined in {{!RFC9711}}. According to that specification, this attribute may be specified multiple times with
different values. However, within the scope of this specification, the "nonce" value can be specified only once within a transaction.

### timestamp

The time at which the PKIX Evidence was generated, according to the internal system clock of the Attester. This is similar to the
"iat" claim in {{!RFC9711}}.

Note that security considerations should be taken relating to the evaluation of timestamps generated by HSMs. See {sec-cons-hsm-timestamps}.

## Additional Entity and Attribute Types {#sec-additional-attr-types}

It is expected that HSM vendors will register additional Entity and Attribute types by assigning OIDs from their own proprietary OID arcs to hold data describing additional proprietary key properties.

When new entity and attribute types are used, documentation similar to the one produced in this specification SHOULD be distributed to
explain the meaning of the types and the frequency that values can be provided.

See {{sec-req-processing}}, {{sec-req-verification}} and {{sec-cons-verifier}} for handling of unrecognized custom types.

## Encoding

A PkixEvidence is to be DER encoded [X.690].

If a textual representation is required, then the DER encoding MAY be subsequently encoded into Base64.

EDNOTE: I think we have to be precise about which flavour of Base64 we are referring to.



# Signing and Verification Procedures {#sec-verif-proc}

The `SignatureBlock.signatureValue` signs over the DER-encoded to-be-signed evidence data
`PkixEvidence.tbs` and MUST be validated with the subject public key of the leaf
X.509 certificate contained in the `SignatureBlock.certChain`.

Note that a PkixEvidence MAY contain zero or more SignatureBlocks.
A PkixEvidence with zero SignatureBlocks is unsigned, MUST be treated as un-protected and un-trusted,
and any signature validation procedure MUST fail.

More than one SignatureBlocks MAY be used to convey a number of different semantics.
For example, the HSM's Attesting Service might hold multiple Attestation Keys on different cryptographic
algorithms in order to provide algorithm redundancy in the case that one algorithm becomes cryptographically broken. In this case a Verifier would be expected to validate all SignatureBlocks. Alternatively, the HSM's Attesting Service may hold multiple Attestation Keys (or multiple X.509 certificates for the same key) from multiple operational environments to which it belongs. In this case a Verifier would be expected to only validate the SignatureBlock corresponding to its own environment. Alternatively, multiple SignatureBlocks could be used to convey counter-signatures from external parties, in which case the Verifier will need to be equipped with environment-specific verification logic. Multiple of these cases, and potentially others, could be supported by a single PkixEvidence object.

Note that each SignatureBlock is a fully detached signature over the tbs content with no binding between the signed content and the SignatureBlocks, or between SignatureBlocks, meaning that a third-party can add a
counter-signature of the evidence after the fact, or an attacker can remove a SignatureBlock without leaving any artifact. See {#sec-detached-sigs} for further discussion.


# Appraisal Policies and Profiles {#sec-profiles}

This section provides some sample profiles of appraisal policies that verifiers
MAY apply when evaluating evidence. These appraisal policy profiles represent environment-specific requirements
on the contents of the evidence and / or endorsement certificate chain.


## Key Import into an HSM

An HSM which is compliant with this draft SHOULD validate any PKIX evidence that is provided
along with the key being imported.

The SignatureBlocks MUST be validated and MUST chain to a trust anchor known to the HSM. In most cases this will
be the same trust anchor that endorsed the HSM's own AK, but the HSM MAY be configured with set of third-party trust anchors from which it will accept key attestations.

If the HSM is operating in FIPS Mode, then it MUST only import keys from HSMs also operating in FIPS Mode.

The claims `key-purpose`, `key-extractable`, `key-never-extractable`, and `key-local` MUST be checked and honoured during key import, which typically means that after import, the key MUST NOT claim a stronger protection property than it had within the previous HSM. In other words, Key Attestation allows and requires that key protection properties be preserved over export / import operations between different HSMs, and this format provides a vendor-agnostic
way to achieve this.

How to handle errors is outside the scope of this specification and is left to implementors; for example the
key import MAY be aborted, or a prompt MAY be given to the user administrator, or any similar reasonable error handling logic may be used.




## CA/Browser Forum Code-Signing

TODO: ... intro text

The subscriber MUST:

* Provide the CA with a CSR containing the subscriber key.
* Provide PKIX evidence, as per this specification, describing the private key protection properties of the subscriber's private key. This evidence MAY be transported inside the CSR as per draft-ietf-lamps-csr-attest, or it MAY be transported adjacent to the CSR over any other certificate enrollment mechanism.

The CA / RA / RP / Verifier MUST:

* Ensure that the subscriber key which is the subject of the CSR is also described by a KAT by matching either the key fingerprint or full SubjectPublicKeyInfo.
* The hardware root-of-trust described by a PAT has a valid and active FIPS certificate according to the NIST CMVP database.
* The attestation key (AK) which has signed the PKIX evidence chains to a root certificate that A) belongs to the hardware vendor described in the PAT token, and B) is trusted by the CA / RA / RP / Verifier to endorse hardware from this vendor, for example through a CA's partner program or through a network operator's device on-boarding process.
* The key is protected by a module running in FIPS mode. The parsing logic is to start at the leaf KAT token that matches the key in the CSR and parsing towards the root PAT ensuring that there is at least one `fipsboot=true` and no `fipsboot=false` on that path.

# Attestation Requests {#sec-reqs}

This section is informative in nature and implementers of this specification do not need to adhere to it. The aim of this section is
to provide a standard interface between a Presenter and an HSM producing PKIX evidence. The authors hope that this standard interface will
yield interoperable tools between offerings from different vendors.

The interface presented in this section might be too complex for manufacturers of HSMs with limited capabilities such as smartcards
or personal ID tokens. For devices with limited capabilities, a fixed PKIX evidence endorsed by the vendor might be installed
during manufacturing. Other approaches for constrained HSMs might be to report entities and attributes that are fixed or offer limited
variations.

On the other hand, an enterprise-grade HSM with the capability to hold a large number of private keys is expected to be capable of generating
PKIX evidence catered to the specific constraints imposed by a Verifier and without exposing extraneous information. The aim of the request
interface is to provide the means to select and report specific information in the PKIX evidence.

This section introduces the role of "Presenter" as shown in {{fig-arch}}. The Presenter is the role that initiates the generation of PKIX
evidence. Since HSMs are generally servers (client/server relationship) or peripherals (controller/peripheral relationship), a Presenter is
required to launch the process of creating the PKIX evidence and capturing it to forward it to the Verifier.

~~~aasvg
+-----------------------------+
|  Attester (HSM)             |
|                             |
|      +--------------+       |
|      | Target       |       |
|      | Environment  |       |
|      | (Entities,&  |       |
|      |  attributes) |       |
|      +-------+------+       |
|              |              |
|              | Collect      |
|              | Claims       |
|              v              |
|      +------------------+   |
|      | Attesting        |   |
|      | Environment      |   |
|      +--------+---------+   |
|            ^  |             |
|            |  |             |
+------------+--+-------------+
             |  |
 Attestation |  |   PKIX
 Request     |  |   Evidence
             |  v
     +----------------+           +------------+
     |    Presenter   |---------->|  Verifier  |
     +----------------+           +------------+
~~~
{: #fig-arch title="Architecture"}


An Attestation Request (request) is assembled by the Presenter and submitted to the HSM. The HSM parses the request and produces PKIX evidence
which is returned to the Presenter for distribution.

The request consists of a structure TbsPkixEvidence containing one ReportedEntity for each entity expected to be included in the evidence produced by the HSM.

Each instance of ReportedEntity included in the request is referred to as a request entity. A request entity contains a number of instances
of ReportedAttribute known as request attributes. The collection of request entities and request attributes represent the information desired
by the Presenter.

In most cases the value of a request attribute should be left unspecified by the Presenter. In the process of generating
the evidence, the values of the desired attributes are observed by the Attestation Service within the HSM and reported accordingly. For the purpose
of creating a request, the Presenter does not specify the value of the requested attributes. This is possible because the definition of
the structure `ReportedAttribute` specifies the element value as optional.

On the other hand, there are circumstances where the value of a request attribute should be provided by the Presenter. For example, when a particular
cryptographic key is to be included in the evidence, the request must include a request entity with one of its attributes set with a type
`id-pkix-evidence-attribute-key-identifier`. The value of this attribute is set to the key identifier associated with the cryptographic
key to be reported.

Some instances of ReportedEntity, such as those representing the platform or the transaction, do not need identifiers as the associated entities are
implicit in nature. Custom entity types might need selection during an attestation request and related documentation should specify how this is
achieved.

The instance of TbsPkixEvidence is unsigned and does not provided any means to maintain integrity when communicated from the Presenter to the HSM.
These details are left to the implementer. However, it is worth pointing out that the structure offered by PkixEvidence could be reused by an
implementer to provide those capabilities, as described in {{sec-cons-auth-the-presenter}}.


## Request Attributes with Specified Values

This section deals with the request attributes specified in this document where a value should be provided by a Presenter. In other words, this
sub-section defines all request attributes that should set in the structure `ReportedAttribute`. Request attributes not covered in this sub-section
should not have a specified value (left empty).

Since this section is non-normative, implementers may deviate from those recommendations.

### Key Identifiers

A Presenter may choose to select which cryptographic keys are reported as part of the PKIX evidence. For each selected cryptographic key,
the Presenter includes a request entity of type `id-pkix-evidence-entity-key`. Among the request attributes for this entity, the
Presenter includes one attribute with the type `id-pkix-evidence-attribute-key-identifier`. The value of this attribute should be
set to the utf8String that represents the identifier for the specific key.

An HSM receiving an attestation request which selects a key via this approach MUST fail the transaction if it cannot find the cryptographic
key associated with the specified identifier.

### Nonce

A Presenter may choose to include a nonce as part of the attestation request. When producing the PKIX evidence, the HSM repeats the
nonce that was provided as part of the request.

When providing a nonce, a Presenter includes, in the attestation request, an entity of type `id-pkix-evidence-entity-transaction`
with an attribute of type `id-pkix-evidence-attribute-transaction-nonce`. This attribute is set with the value of the
nonce as "bytes".

### Custom Key Selection

An implementer might desire to select multiple cryptographic keys based on a shared attribute. A possible approach
is to include a single request entity of type `id-pkix-evidence-entity-key` including an attribute with a set value. This attribute
would not be related to the key identifier as this is unique to each key. A HSM supporting this scheme could select all the cryptographic
keys matching the specified attribute and report them in the PKIX evidence.

This is a departure from the base request interface, as multiple key entities are reported from a single request entity.

More elaborate selection schemes are envisaged where multiple request attributes specifying values would be tested against cryptographic keys.
Whether these attributes are combined in a logical "and" or in a logical "or" would need to be specified by the implementer.

### Custom Transaction Entity Attributes

The extensibility offered by the proposed request interface allows an implementer to add custom attributes to the transaction entity in
order to influence the way that the evidence generation is performed.

In such an approach, a new custom attribute for request entities of type `id-pkix-evidence-entity-transaction` is defined. Then, an
attribute of that type is included in the attestation request (as part of the transaction entity) while specifying a value. This value
is considered by the HSM while generating the PKIX evidence.

## Processing an Attestation Request {#sec-req-processing}

This sub-section deals with the rules that should be considered when an Attester (the HSM) processes a request to generate an
attestation request. This section is non-normative and implementers MAY choose to not follow these recommendations.

These recommendations apply to any attestation request schemes and are not restricted solely to the request interface proposed
here.

An Attester MUST fail an attestation request if it contains an unrecognized entity type. This is to ensure that all the semantics expected
by the Presenter are fully understood by the Attester.

An Attester MUST fail an attestation request if it contains a request attribute of an unrecognized type with a specified a value (not
empty). This represents a situation where the Presenter is selecting specific information that is not understood by the Attester.

An Attester SHOULD ignore unrecognized attribute types in an attestation request. In this situation, the Attester SHOULD NOT include
the attribute as part of the response. This guidance is to increase the likelihood of interoperability between tools of various
vendors.

An Attester MUST NOT include entities and attributes in the generated evidence if these entities and attributes were
not specified as part of the request. This is to give the Presenter the control on what information is disclosed by the Attester.

An Attester MUST fail an attestation request if the Presenter does not have the appropriate access rights to the entities included
in the request.


## Verification by Presenter {#sec-req-verification}

This sub-section deals with the rules that should be considered when a Presenter receives PKIX evidence from the Attester (the HSM)
prior to distribution. This section is non-normative and implementers MAY choose to not follow these recommendations.

These recommendations apply to any PKIX evidence and are not restricted solely to evidence generated from the proposed request interface.

A Presenter MUST review the evidence produced by an Attester for fitness prior to distribution.

A Presenter MUST NOT disclose evidence if it contains information it
cannot parse. This restriction applies to entity types and attributes type. This is
to ensure that the information provided by the Attester can be evaluated by the
Presenter.

A Presenter MUST NOT disclose evidence if it contains entities others
than the ones that were requested of the Attester. This is to ensure that only the
selected entities are exposed to the Verifier.

A Presenter MUST NOT disclose evidence if it contains an entity with an attribute
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

TODO: list out all the OIDs that need IANA registration.

# Security Considerations

## Policies relating to Verifier and Relying Party {#sec-cons-verifier}

The generation of PKIX evidence by an HSM is to provide sufficient information to
a Verifier and a Relying Party to appraise the Target Environment (the HSM) and make
decisions based on this appraisal.

The Appraisal Policy associated with the Verifier influences the generation of the Attestation
Results. Those results, in turn, are consumed by the Relying Party to make decisions about
the HSM, which might be based on a set of rules and policies. Therefore, the interpretation of
PKIX evidence may greatly influence the outcome of some decisions.

A Verifier MAY reject a PKIX evidence if it lacks required attributes per the Verifier's
appraisal policy. For example, if a Relying Party mandates a FIPS-certified device,
it SHOULD reject evidence lacking sufficient information to verify the device's FIPS
certification status.

If a Verifier encounters an attribute with an unrecognized attribute type, it MAY ignore it and
treat it as extraneous information. By ignoring an attribute, the Verifier may accept PKIX evidence
that would be deemed malformed to a Verifier with different policies. However, this approach
fosters a higher likelihood of achieving interoperability.

## Simple to Implement {#sec-cons-simple}

The nature of attestation requires the Attestation Service to be implemented in an extremely
privileged position within the HSM so that it can collect measurements of both the hardware
environment and the user keys being attested. For many HSM architectures, this will
place the Attestation Service inside the "security kernel" and potentially subject to FIPS 140-3
or Common Criteria validation and change control. For both security and compliance reasons
there is incentive for the generation and parsing logic to be simple and easy to implement
correctly. Additionally, when the data formats contained in this specification are parsed
within an HSM boundary -- that would be parsing a request entity, or parsing an attestation
produced by a different HSM -- implementers SHOULD opt for simple logic that rejects any
data that does not match the expected format, instead of attempting to be flexible.

In particular, the Attestation Service SHOULD generate the PKIX evidence from scratch and
avoid copying any content from the request. The Attestation Service MUST generate PKIX evidence
only from attributes and values that are observed by the service.

## Detached Signatures {#sec-detached-sigs}

TODO: Editorial work needed.

No indication within the tbs content about what or how many signatures to expect.

A SignatureBlock can be trivially stripped off without leaving any evidence.

When multiple SignatureBlocks are used for providing third-party counter-signatures, note that the counter signature only covers the tbs content and not existing SignatureBlocks.

## Privacy {#sec-cons-privacy}

Some HSMs have the capacity of supporting cryptographic keys controlled by separate entities referred to as "tenants", and when the HSM is used in that mode
it is referred to as a multi-tenant configuration.

For example, an enterprise-grade HSM in a large multi-tenant cloud service could host TLS keys fronting multiple un-related web domains. Providing evidence for
attesting attributes of any one of the keys would involve a Presenter that could potentially access any of the hosted keys.
In such a case, private violations could occur if the Presenter was to disclose information that does not relate to the subject key.

Implementers SHOULD be careful to avoid over-disclosure of information, for example by authenticating the Presenter as described in {{sec-cons-auth-the-presenter}} and only returning results for keys and environments for which it is authorized.
In absence of an existing mechanism for authenticating and authorizing administrative connections to the HSM, the attestation request MAY be authenticated by embedding the TbsPkixEvidence of the request inside a PkixEvidence signed with a certificate belonging to the Presenter.

Furthermore, enterprise and cloud-services grade HSMs SHOULD support the full set of attestation request functionality described in {{sec-reqs}} so that Presenters can fine-tune the content of a PKIX evidence such that it is appropriate for the intended Verifier.


## Authenticating and Authorizing the Presenter {#sec-cons-auth-the-presenter}

The Presenter represents a privileged role within the architecture of this specification as it gets to learn about the existence of user keys and their protection properties, as well as details of the platform.
The Presenter is in the position of deciding how much information to disclose to the Verifier, and to request a suitably redacted evidence from the HSM.

For personal cryptographic tokens it might be appropriate for the attestation request interface to be un-authenticated. However, for enterprise and cloud-services grade HSMs the Presenter SHOULD be authenticated using the HSM's native authentication mechanism. The details are HSM-specific and are thus left up to the implementer. However, it is RECOMMENDED to implement an authorization framework similar to the following.

A Presenter SHOULD be allowed to request evidence for any user keys which it is allowed to use.
For example, a TLS application that is correctly authenticated to the HSM in order to use its TLS keys SHOULD be able to request evidence of those same keys without needing to perform any additional authentication or requiring any additional roles or permissions.
HSMs that wish to allow a Presenter to request evidence of keys which is not allowed to use, for example for the purposes of displaying HSM status information on an administrative console or UI, SHOULD have a "Attestation Requester" role or permission and SHOULD enforce the HSM's native access controls such that the Presenter can only retrieve evidence for keys for which it has read access.

In the absence of an existing mechanism for authenticating and authorizing administrative connections to the HSM, the attestation request MAY be authenticated by embedding the ClaimDescriptionTbs of the request inside a PkixEvidence signed with a certificate belonging to the Presenter.

## Proof-of-Possession of User Keys

With asymmetric keys within a Public Key Infrastructure (PKI) it is common to require a key holder to prove that they are in control of the private key by using it. This is called "proof-of-possession (PoP)". This specification intentionally does not provide a mechanism for PoP of user keys and relies on the Presenter, Verifier, and Relying Party trusting the Attester to correctly report the cryptographic keys that it is holding.

It would be easy to add a PoP Key Attribute that uses the attested user key to sign over, for example, the Transaction Entity. However, this is a bad idea and MUST NOT be added as a custom attribute for several reasons.

First, an application key intended, for example, for TLS SHOULD only be used with the TLS protocol and introducing a signature oracle whereby the TLS application key is used to sign PKIX evidence could lead to cross-protocol attacks whereby the attacker submits a nonce value which is in fact not random but is crafted in such a way as to appear as a valid message in some other protocol context or exploit some other weakness in the signature algorithm.

Second, the Presenter who has connected to the HSM to request PKIX evidence may have permissions to view the requested application keys but not permission to use them, as in the case where the Presenter is an administrative UI displaying HSM status information to an systems administrator or auditor.

Requiring the Attestation Service to use the attested application keys could, in some architectures, require the Attestation Service to resolve complex access control logic and handle complex error conditions for each requested key, which violates the "simple to implement" design principle outlined in {{sec-cons-simple}}. More discussion of authenticating the Presenter can be found in {{sec-cons-auth-the-presenter}}.

## Timestamps and HSMs {#sec-cons-hsm-timestamps}

It is common for HSMs to have an inaccurate system clock. Most clocks have a natural drift and must be corrected periodically. HSMs, like any other devices,
are subject to these issues.

There are many situations where HSMs can not naturally correct their internal system clocks. For example, consider a HSM hosting a trust anchor and usually kept offline
and booted up infrequently in an network without a reliable time management service. Another example is a smart card which boots up only when held against an NFC reader.

When a timestamp generated from a HSM is evaluated, the expected behavior of the system clock SHOULD be considered.

More specifically, the timestamp SHOULD NOT be relied on for establishing the freshness of the evidence generated by a HSM. Instead, Verifiers SHOULD rely on other provisions
such as the "nonce" attribute of the "transaction" entity, introduced this specification.

--- back

# Samples

A reference implementation of this specification can be found at https://github.com/ietf-rats-wg/key-attestation

It produces the following sample evidence:

~~~
{::include-fold sampledata/idea3/sample1.txt}
~~~

# Acknowledgements

This specification is the work of a design team created by the chairs
of the RATS working group. This specification has been developed
based on discussions in that design team and also with great amounts of
input taken from discussions on the RATS mailing list.

We would like to thank Jeff Andersen for the review comments.
