
from pyasn1.type import namedval
from pyasn1.type import useful
from pyasn1.type import univ, char, namedtype, constraint, tag

from pyasn1_alt_modules import rfc2986, rfc5280, rfc5751, rfc8017, pem

MAX = 100

# ASN.1 Module


# CHANGE ME
PKIX_ATTEST_OID_ARC = univ.ObjectIdentifier((1, 2, 3, 999))

## Envelope

class KeyProtectionClaim(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Any())
    )

class PlatformClaim(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Any())
    )

# Fingerprint ::= SEQUENCE {
#     hashAlg AlgorithmIdentifier,
#     fingerprint OCTET STRING
# }
class Fingerprint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("hashAlg", rfc5280.AlgorithmIdentifier()),
        namedtype.OptionalNamedType("value", univ.OctetString())
    )


# KeyDescription ::= SEQUENCE {
#     spki        [0] SubjectPublicKeyInfo OPTIONAL,
#     fingerprint [1] Fingerprint OPTIONAL,
#     keyID       [2] IA5String OPTIONAL,
#     description [3] UTF8String
# }
class KeyDescription(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("spki", rfc5280.SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType("fingerprint", Fingerprint()),
        namedtype.OptionalNamedType("keyID", char.IA5String()),
        namedtype.OptionalNamedType("description", char.UTF8String())
    )


# KeyEnvironmentDescription ::= SEQUENCE {
#     environmentID [0] IA5String OPTIONAL,
#     description   [1] UTF8String OPTIONAL
# }
class KeyEnvironmentDescription(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("environmentID", char.IA5String()),
        namedtype.OptionalNamedType("description", char.UTF8String())
    )

# SingleKeyAttestation ::= SEQUENCE {
#     keyDescription KeyDescription,
#     protectionClaims SEQUENCE SIZE (0..MAX) of KeyProtectionClaim,
#     environment SEQUENCE SIZE (0..MAX) of KeyEnvironmentDescription
# }
class SingleKeyAttestation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("keyDescription", KeyDescription()),
        namedtype.NamedType("protectionClaims", univ.SequenceOf(
            componentType = KeyProtectionClaim(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        )),
        namedtype.NamedType("environment", univ.SequenceOf(
            componentType = KeyEnvironmentDescription(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        ))
    )


# SignatureBlock ::= SEQUENCE {
#    certChain SEQUENCE of Certificate,
#    signatureAlgorithm AlgorithmIdentifier,
#    signatureValue OCTET STRING
# }
class SignatureBlock(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("certChain", univ.SequenceOf(
            componentType = rfc5280.Certificate(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        )),
        namedtype.NamedType("signatureAlgorithm", rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType("signatureValue", univ.OctetString())
    )


# PkixKeyAttestation ::= SEQUENCE {
#     version INTEGER,
#     keys SEQUENCE SIZE (1..MAX) OF SingleKeyAttestation,
#     platformClaims SEQUENCE SIZE (0..MAX) OF PlatformClaim,
#     signatures SEQUENCE SIZE (1..MAX) of SignatureBlock
# }
class PkixKeyAttestation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("keys", univ.SequenceOf(
            componentType = SingleKeyAttestation(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        )),
        namedtype.NamedType("platformClaims", univ.SequenceOf(
            componentType = PlatformClaim(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        )),
        namedtype.NamedType("signatures", univ.SequenceOf(
            componentType = SignatureBlock(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        ))
    )








# Claims

# TODO: define OIDs and ASN.1 for all the EAT claims I'm borrowing.

    
id_pkixattest_fipsboot = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (2,))
class PkixClaim_fipsboot(PlatformClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )
    type = id_pkixattest_fipsboot

id_pkixattest_nonce = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (4,))
class PkixClaim_nonce(PlatformClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.IA5String())
    )
    type = id_pkixattest_nonce

id_pkixattest_attestationTime = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (5,))
class PkixClaim_attestationTime(PlatformClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', useful.GeneralizedTime())
    )
    type = id_pkixattest_attestationTime,


id_pkixattest_purpose = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (10,))
class PkixClaim_purpose(KeyProtectionClaim):
    class Value(univ.BitString):
        pass
    Value.namedValues = namedval.NamedValues(
        ('Sign', 0),
        ('Verify', 1),
        ('Encrypt', 2),
        ('Decrypt', 3),
        ('Wrap', 4),
        ('Unwrap', 5),
        ('Encapsulate', 6),
        ('Decapsulate', 7),
        ('Derive', 8)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', Value())
    )


id_pkixattest_extractable = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (11,))
class PkixClaim_extractable(KeyProtectionClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )
    type = id_pkixattest_extractable

id_pkixattest_neverExtractable = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (12,))
class PkixClaim_neverExtractable(KeyProtectionClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )

id_pkixattest_imported = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (13,))
class PkixClaim_imported(KeyProtectionClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )
    type = id_pkixattest_imported

id_pkixattest_keyexpiry = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (14,))
class PkixClaim_keyExpiry(KeyProtectionClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', useful.GeneralizedTime())
    )
    type = id_pkixattest_imported


id_pkixattest_keydescription = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (15,))
class PkixClaim_keyDescription(KeyProtectionClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )
    type = id_pkixattest_keydescription


id_pkixattest_hwvendor = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (16,))
class PkixClaim_hwvendor(PlatformClaim):
        componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )

id_pkixattest_hwmodel = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (17,))
class PkixClaim_hwmodel(PlatformClaim):
        componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )

id_pkixattest_hwserial = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (18,))
class PkixClaim_hwserial(PlatformClaim):
        componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )
    

id_pkixattest_envDescription = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (19,))
class PkixClaim_envDescription(PlatformClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )



id_pkixattest_keyProtection = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (21,)) 
class PkixClaim_keyProtection(KeyProtectionClaim):
    class Value(univ.BitString):
        pass
    Value.namedValues = namedval.NamedValues(
        ('DualControl', 0),
        ('CardControl', 1),
        ('PasswordControl', 2)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', Value())
    )