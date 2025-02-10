
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

id_pkix_attest_attribute_platform            = univ.ObjectIdentifier( id_pkix_attest_attribute_type + (1,))
id_pkix_attest_attribute_platform_hwserial   = univ.ObjectIdentifier( id_pkix_attest_attribute_platform + (0,))
id_pkix_attest_attribute_platform_fipsboot   = univ.ObjectIdentifier( id_pkix_attest_attribute_platform + (1,))
id_pkix_attest_attribute_platform_desc       = univ.ObjectIdentifier( id_pkix_attest_attribute_platform + (2,))
id_pkix_attest_attribute_platform_time       = univ.ObjectIdentifier( id_pkix_attest_attribute_platform + (3,))
id_pkix_attest_attribute_platform_fw_version = univ.ObjectIdentifier( id_pkix_attest_attribute_platform + (4,))

id_pkix_attest_attribute_key                   = univ.ObjectIdentifier( id_pkix_attest_attribute_type + (2,))
id_pkix_attest_attribute_key_identifier        = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (0,))
id_pkix_attest_attribute_key_spki              = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (1,))
id_pkix_attest_attribute_key_purpose           = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (2,))
id_pkix_attest_attribute_key_extractable       = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (3,))
id_pkix_attest_attribute_key_never_extractable = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (4,))
id_pkix_attest_attribute_key_local             = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (5,))
id_pkix_attest_attribute_key_expiry            = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (6,))
id_pkix_attest_attribute_key_protection        = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (7,))

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
#    bool        [2] IMPLICIT BOOLEAN,
#    time        [3] IMPLICIT GeneralizedTime,
#    value       [4] IMPLICIT INTEGER,
#    oid         [5] IMPLICIT OBJECT IDENTIFIER
# }
class AttributeValue(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bytes', univ.OctetString()),
        namedtype.NamedType('utf8String', char.UTF8String()),
        namedtype.NamedType('bool', univ.Boolean()),
        namedtype.NamedType('time', useful.GeneralizedTime()),
        namedtype.NamedType('value', univ.Integer()),
        namedtype.NamedType('oid', univ.ObjectIdentifier())
    )
    
    def setBytes(self, value:bytes) -> "AttributeValue":
        self["bytes"] = univ.OctetString(value)
        return self
    
    def setString(self, value:str) -> "AttributeValue":
        self["utf8String"] = value
        return self
    
    def setInteger(self, value:int) -> "AttributeValue":
        self["value"] = value
        return self
    
    def setBoolean(self, flag:bool) -> "AttributeValue":
        self["bool"] = flag
        return self
    
    def setTime(self, time:str) -> "AttributeValue":
        self["time"] = time
        return self
    
# ReportedAttribute ::= SEQUENCE {
#     attributeType      OBJECT IDENTIFIER,
#     value              AttributeValue
# }
class ReportedAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attributeType", univ.ObjectIdentifier()),
        namedtype.NamedType("value", AttributeValue())
    )

#
# Generic Attributes
#

def ReportedAttributeBytes(oid:univ.ObjectIdentifier, valueBytes:bytes):
    attribute = ReportedAttribute()
    attribute["attributeType"] = oid
    attribute["value"] = AttributeValue().setBytes(valueBytes)
    return attribute

def ReportedAttributeString(oid:univ.ObjectIdentifier, valueStr:str):
    attribute = ReportedAttribute()
    attribute["attributeType"] = oid
    attribute["value"] = AttributeValue().setString(valueStr)
    return attribute

def ReportedAttributeInteger(oid:univ.ObjectIdentifier, valueInt:int):
    attribute = ReportedAttribute()
    attribute["attributeType"] = oid
    attribute["value"] = AttributeValue().setInteger(valueInt)
    return attribute

def ReportedAttributeBoolean(oid:univ.ObjectIdentifier, valueBool:bool):
    attribute = ReportedAttribute()
    attribute["attributeType"] = oid
    attribute["value"] = AttributeValue().setBoolean(valueBool)
    return attribute

def ReportedAttributeTime(oid:univ.ObjectIdentifier, valueTime:str):
    attribute = ReportedAttribute()
    attribute["attributeType"] = oid
    attribute["value"] = AttributeValue().setTime(valueTime)
    return attribute

#
# Request Attributes
#
    
def ReportedAttributeRequestNonce(nonce:bytes):
    return ReportedAttributeBytes(
        id_pkix_attest_attribute_request_nonce,
        nonce
    )
    
#
# Platform Attributes
#
    
def ReportedAttributePlatformSerial(serialNumber:str):
    return ReportedAttributeString(
        id_pkix_attest_attribute_platform_hwserial,
        serialNumber
    )
    
def ReportedAttributePlatformFipsBoot(flag:bool):
    return ReportedAttributeBoolean(
        id_pkix_attest_attribute_platform_fipsboot,
        flag
    )
    
def ReportedAttributePlatformDescription(desc:str):
    return ReportedAttributeString(
        id_pkix_attest_attribute_platform_desc,
        desc
    )
    
def ReportedAttributePlatformFwVersion(version:str):
    return ReportedAttributeString(
        id_pkix_attest_attribute_platform_fw_version,
        version
    )
    
def ReportedAttributePlatformTime(time:str):
    return ReportedAttributeTime(
        id_pkix_attest_attribute_platform_time,
        time
    )
    
#
# Key Attributes
#
    
def ReportedAttributeKeyIdentifier(id:str):
    return ReportedAttributeString(
        id_pkix_attest_attribute_key_identifier,
        id
    )
    
def ReportedAttributeKeySPKI(spki:bytes):
    return ReportedAttributeBytes(
        id_pkix_attest_attribute_key_spki,
        spki
    )
    
def ReportedAttributeKeyExtractable(flag:bool):
    return ReportedAttributeBoolean(
        id_pkix_attest_attribute_key_extractable,
        flag
    )
    
def ReportedAttributeKeyNeverExtractable(flag:bool):
    return ReportedAttributeBoolean(
        id_pkix_attest_attribute_key_never_extractable,
        flag
    )
    
def ReportedAttributeKeyLocal(flag:bool):
    return ReportedAttributeBoolean(
        id_pkix_attest_attribute_key_local,
        flag
    )

# id_pkix_attest_attribute_key_purpose           = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (2,))
# id_pkix_attest_attribute_key_expiry            = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (6,))
# id_pkix_attest_attribute_key_protection        = univ.ObjectIdentifier( id_pkix_attest_attribute_key + (7,))

# ReportedEntity ::= SEQUENCE {
#     entityType         OBJECT IDENTIFIER,
#     reportedAttributes SEQUENCE SIZE (1..MAX) OF ReportedAttribute
# }
class ReportedEntity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("entityType", univ.ObjectIdentifier()),
        namedtype.NamedType("reportedAttributes", univ.SequenceOf(
            componentType = ReportedAttribute(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        ))
    )
    
    def addAttribute(self, attribute) -> "ReportedEntity":
        self["reportedAttributes"].append(attribute)
        return self
    
def ReportedEntityGeneric(entityType:univ.ObjectIdentifier) -> "ReportedEntity":
    entity = ReportedEntity()
    entity["entityType"] = entityType
    return entity
    
def ReportedEntityRequest() -> "ReportedEntity":
    return ReportedEntityGeneric(id_pkix_attest_entity_request)
    
def ReportedEntityPlatform() -> "ReportedEntity":
    return ReportedEntityGeneric(id_pkix_attest_entity_platform)
    
def ReportedEntityKey() -> "ReportedEntity":
    return ReportedEntityGeneric(id_pkix_attest_entity_key)

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
    
    def __init__(self, **kwargs):
        univ.Sequence.__init__(self, **kwargs)
        
        # Defaults to 2 to avoid collision with legacy implementations
        self.setVersion(2)
    
    def setVersion(self, version:int) -> "TbsPkixAttestation":
        self["version"] = version
        return self
    
    def addEntity(self, entity) -> "TbsPkixAttestation":
        self["reportedEntities"].append(entity)
        return self

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



