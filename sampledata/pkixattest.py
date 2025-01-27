
from pyasn1.type import namedval
from pyasn1.type import useful
from pyasn1.type import univ, char, namedtype, constraint, tag

from pyasn1_alt_modules import rfc2986, rfc5280, rfc5751, rfc8017, pem

MAX = 100

# ASN.1 Module


# CHANGE ME
PKIX_ATTEST_OID_ARC = univ.ObjectIdentifier((1, 2, 3, 999))

## Envelope

class PkixClaim(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Any())
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

class SetOfClaims(univ.SequenceOf):
    componentType = PkixClaim()
    subtypeSpec = constraint.ValueSizeConstraint(0, MAX)


# PkixAttestation ::= SEQUENCE {
#   version INTEGER,
#   claims SetOfClaims,
#   signatures SEQUENCE SIZE (1..MAX) OF SignatureBlock,
# }
class PkixAttestation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("claims", SetOfClaims()),
        namedtype.NamedType("signatures", univ.SequenceOf(
            componentType = SignatureBlock(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        ))
    )
    # def __init__(self, **kwargs):
    #     super().__init__(**kwargs)
    #     self['signatures'] = univ.SequenceOf(
    #         componentType = SignatureBlock()
    #     )



# Claims

# TODO: define OIDs and ASN.1 for all the EAT claims I'm borrowing.

    
id_pkixattest_fipsboot = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (2,))
class PkixClaim_fipsboot(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )
    type = id_pkixattest_fipsboot

id_pkixattest_nestedTokens = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (3,))
class PkixClaim_nestedTokens(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.SequenceOf(
            componentType = PkixAttestation(),
            subtypeSpec = constraint.ValueSizeConstraint(1, MAX)
        ) )
    )
    type = id_pkixattest_nestedTokens

id_pkixattest_nonce = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (4,))
class PkixClaim_nonce(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.IA5String())
    )
    type = id_pkixattest_nonce

id_pkixattest_attestationTime = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (5,))
class PkixClaim_attestationTime(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', useful.GeneralizedTime())
    )
    type = id_pkixattest_attestationTime,

id_pkixattest_keyid = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (6,))
class PkixClaim_keyID(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.IA5String())
    )
    type = id_pkixattest_keyid

id_pkixattest_pubKey = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (7,))
class PkixClaim_pubKey(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', rfc5280.SubjectPublicKeyInfo())
    )


id_pkixattest_keyFingerprintAlg = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (8,))
class PkixClaim_keyFingerprintAlg(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', rfc5280.AlgorithmIdentifier())
    )
    type = id_pkixattest_keyFingerprintAlg

id_pkixattest_keyFingerprint = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (9,))
class PkixClaim_keyFingerprint(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.OctetString())
    )


id_pkixattest_purpose = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (10,))
class PkixClaim_purpose(PkixClaim):
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
class PkixClaim_extractable(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )
    type = id_pkixattest_extractable

id_pkixattest_neverExtractable = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (12,))
class PkixClaim_neverExtractable(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )

id_pkixattest_imported = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (13,))
class PkixClaim_imported(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )
    type = id_pkixattest_imported

id_pkixattest_keyexpiry = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (14,))
class PkixClaim_keyExpiry(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', useful.GeneralizedTime())
    )
    type = id_pkixattest_imported


id_pkixattest_keydescription = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (15,))
class PkixClaim_keyDescription(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )
    type = id_pkixattest_keydescription


id_pkixattest_hwvendor = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (16,))
class PkixClaim_hwvendor(PkixClaim):
        componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )

id_pkixattest_hwmodel = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (17,))
class PkixClaim_hwmodel(PkixClaim):
        componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )

id_pkixattest_hwserial = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (18,))
class PkixClaim_hwserial(PkixClaim):
        componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )
    

id_pkixattest_envDescription = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (19,))
class PkixClaim_envDescription(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )

id_pkixattest_keyDescription = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (20,))
class PkixClaim_keyDescription(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.UTF8String())
    )


id_pkixattest_keyProtection = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (21,)) 
class Value(univ.BitString):
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