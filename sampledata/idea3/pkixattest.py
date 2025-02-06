
from pyasn1.type import namedval
from pyasn1.type import useful
from pyasn1.type import univ, char, namedtype, constraint, tag

from pyasn1_alt_modules import rfc2986, rfc5280, rfc5751, rfc8017, pem

MAX = 100

# ASN.1 Module


# CHANGE ME
PKIX_ATTEST_OID_ARC = univ.ObjectIdentifier((1, 2, 3, 999))
id_pkix_attest = univ.ObjectIdentifier((1, 2, 3, 999))

id_pkix_attest_entity_type = univ.ObjectIdentifier( id_pkix_attest + (0,))

id_pkix_attest_entity_request  = univ.ObjectIdentifier( id_pkix_attest_entity_type + (0,))
id_pkix_attest_entity_platform = univ.ObjectIdentifier( id_pkix_attest_entity_type + (1,))
id_pkix_attest_entity_key      = univ.ObjectIdentifier( id_pkix_attest_entity_type + (2,))

id_pkix_attest_attribute_type = univ.ObjectIdentifier( id_pkix_attest + (1,))

id_pkix_attest_attribute_request        = univ.ObjectIdentifier( id_pkix_attest_attribute_type + (0,))
id_pkix_attest_attribute_request_nonce  = univ.ObjectIdentifier( id_pkix_attest_attribute_request + (0,))

id_pkix_attest_attribute_platform          = univ.ObjectIdentifier( id_pkix_attest_attribute_type + (1,))
id_pkix_attest_attribute_platform_hwserial = univ.ObjectIdentifier( id_pkix_attest_attribute_platform + (0,))
id_pkix_attest_attribute_platform_fipsboot = univ.ObjectIdentifier( id_pkix_attest_attribute_platform + (1,))
id_pkix_attest_attribute_platform_desc     = univ.ObjectIdentifier( id_pkix_attest_attribute_platform + (2,))
id_pkix_attest_attribute_platform_time     = univ.ObjectIdentifier( id_pkix_attest_attribute_platform + (3,))

id_pkix_attest_attribute_key                   = univ.ObjectIdentifier( id_pkix_attest_attribute_type + (2,))
id_pkix_attest_attribute_key_spki              = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (0,))
id_pkix_attest_attribute_key_purpose           = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (1,))
id_pkix_attest_attribute_key_extractable       = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (2,))
id_pkix_attest_attribute_key_never_extractable = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (3,))
id_pkix_attest_attribute_key_local             = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (4,))
id_pkix_attest_attribute_key_expiry            = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (5,))
id_pkix_attest_attribute_key_protection        = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (6,))

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

# AttributeValue :== CHOICE {
#    bytes       [0] IMPLICIT OCTET STRING,
#    utf8String  [1] IMPLICIT UTF8String,
#    time        [2] IMPLICIT GeneralizedTime,
#    value       [3] IMPLICIT INTEGER
# }
class AttributeValue(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bytes', univ.OctetString()),
        namedtype.NamedType('utf8String', char.UTF8String()),
        namedtype.NamedType('time', useful.GeneralizedTime()),
        namedtype.NamedType('value', univ.Integer())
    )
    
# ReportedAttribute ::= SEQUENCE {
#     attributeType      OBJECT IDENTIFIER,
#     value              AttributeValue
# }
class ReportedAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attributeType", univ.ObjectIdentifier()),
        namedtype.NamedType("value", AttributeValue())
    )
    
def ReportedAttributePlatformSerial(serialNumber:str):
    attribute = ReportedAttribute()
    attribute["attributeType"] = id_pkix_attest_attribute_platform_hwserial
    attValue = AttributeValue()
    attValue["utf8String"] = serialNumber
    attribute["value"] = attValue
    return attribute
    
def ReportedAttributeKeyExtractable(flag:bool):
    attribute = ReportedAttribute()
    attribute["attributeType"] = id_pkix_attest_attribute_key_extractable
    attValue = AttributeValue()
    if( flag ):
        attValue["value"] = 1
    else:
        attValue["value"] = 0
    attribute["value"] = attValue
    return attribute

# ReportedEntity ::= SEQUENCE {
#     entityType         OBJECT IDENTIFIER,
#     reportedAttributes SEQUENCE SIZE (1..MAX) OF ReportedAttribute
# }
class ReportedEntity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("entityType", univ.ObjectIdentifier()),
        namedtype.NamedType("reportedAttributes", univ.SequenceOf(
            componentType = SingleKeyAttestation(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        ))
    )
    
def ReportedEntityPlatform():
    entity = ReportedEntity()
    entity["entityType"] = id_pkix_attest_entity_platform
    return entity
    
def ReportedEntityKey():
    entity = ReportedEntity()
    entity["entityType"] = id_pkix_attest_entity_key
    return entity

# TbsPkixAttestation ::= SEQUENCE {
#     version INTEGER,
#     reportedEntities SEQUENCE SIZE (1..MAX) OF ReportedEntity
# }
class TbsPkixAttestation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("reportedEntities", univ.SequenceOf(
            componentType = ReportedEntity(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        ))
    )

# PkixAttestation ::= SEQUENCE {
#     tbs TbsPkixAttestation,
#     signatures SEQUENCE SIZE (0..MAX) of SignatureBlock
# }
class PkixAttestation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tbs", TbsPkixAttestation()),
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