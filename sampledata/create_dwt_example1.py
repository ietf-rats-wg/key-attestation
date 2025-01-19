import sys
import argparse

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import asymmetric, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, utils

import hashlib, base64
# from ecdsa.util import sigencode_der

from pyasn1.type import univ, char, namedtype, constraint, tag
from pyasn1.codec.der import decoder 
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

from pyasn1.type import namedval
from pyasn1.type import useful
from pyasn1_alt_modules import rfc2986, rfc5280, rfc5751, rfc8017, pem


# CHANGE ME
PKIX_ATTEST_OID_ARC = univ.ObjectIdentifier((1, 2, 3, 999))


MAX = 10

# ASN.1 Module

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

id_pkixattest_hwserial = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (1,))
class PkixClaim_hwSerial(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.IA5String())
    )
    type = id_pkixattest_hwserial

    
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
    type = id_pkixattest_keyFingerprint


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
    type = id_pkixattest_keyFingerprint


id_pkixattest_extractable = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (11,))
class PkixCaim_extractable(PkixClaim):
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
    type = id_pkixattest_neverExtractable

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




# Load the RSA and P256 certs

def loadCertFromPemFile(file):
    idx, substrate = pem.readPemBlocksFromFile(
        open(file, "r"), ('-----BEGIN CERTIFICATE-----',
                    '-----END CERTIFICATE-----')
    )
    if not substrate:
        return None
    
    cert, rest = decoder.decode(substrate, asn1Spec=rfc5280.Certificate())

    return cert

rsaCert = loadCertFromPemFile('rfc9500_rsa.crt')
p256Cert = loadCertFromPemFile('rfc9500_p256.crt')

with open("rfc9500_rsa.priv", "rb") as key_file:
    rsaPrivkey = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

with open("rfc9500_p256.priv", "rb") as key_file:
    p256Privkey = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )


# Extract the SPKIs and pub keys from the RSA and P256 certs

rsaSPKI = rsaCert['tbsCertificate']['subjectPublicKeyInfo']
p256SPKI = p256Cert['tbsCertificate']['subjectPublicKeyInfo']

rsaPubKey = rsaSPKI['subjectPublicKey']
p256PubKey = p256SPKI['subjectPublicKey']



# Construct KAT1 token

# {
#   "keyID": "18",
#   "pubKey": <SPKI>,
#   "keyFingerprintAlg": AlgorithmID(id-sha256),
#   "keyFingerprint": 0x1a2b3c,
#   "purpose": {Sign},
#   "extractable": true,
#   "neverExtractable": false,
#   "imported": false
# }

kat1 = PkixAttestation()
kat1["version"] = 1

kat1Claims = SetOfClaims()

claim = PkixClaim_keyID()
claim['type'] = id_pkixattest_keyid
claim['value'] = char.IA5String('18')
kat1Claims.append(claim)

claim = PkixClaim_pubKey()
claim['type'] = id_pkixattest_pubKey
claim['value'] = rsaSPKI
kat1Claims.append(claim)


claim = PkixClaim_keyFingerprintAlg()
claim['type'] = id_pkixattest_keyFingerprintAlg
algID = rfc5280.AlgorithmIdentifier()
algID['algorithm'] = rfc8017.id_sha256
claim['value'] = algID
kat1Claims.append(claim)


fingerprint = hashlib.sha256(bytes(rsaSPKI['subjectPublicKey']))
claim = PkixClaim_keyFingerprint()
claim['type'] = id_pkixattest_keyFingerprint
claim['value'] = univ.OctetString(fingerprint.digest())
kat1Claims.append(claim)

claim = PkixClaim_purpose()
claim['type'] = id_pkixattest_purpose
claim['value'] = PkixClaim_purpose.Value.namedValues['Sign']
kat1Claims.append(claim)

claim = PkixCaim_extractable()
claim['type'] = id_pkixattest_extractable
claim['value'] = univ.Boolean(True)
kat1Claims.append(claim)

claim = PkixClaim_neverExtractable()
claim['type'] = id_pkixattest_neverExtractable
claim['value'] = univ.Boolean(False)
kat1Claims.append(claim)

claim = PkixClaim_imported()
claim['type'] = id_pkixattest_imported
claim['value'] = univ.Boolean(False)
kat1Claims.append(claim)


claim = PkixClaim_nonce()
claim['type'] = id_pkixattest_nonce
claim['value'] = char.IA5String("987654321")
kat1Claims.append(claim)

claim = PkixClaim_attestationTime()
claim['type'] = id_pkixattest_attestationTime
claim['value'] = useful.GeneralizedTime(useful.UTCTime.fromDateTime(datetime.now()))
kat1Claims.append(claim)

kat1['claims'] = kat1Claims
signatures = univ.SequenceOf(
                    componentType = SignatureBlock(),
                    subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
                )


# Sign with the RSA key

signature = rsaPrivkey.sign(
    encode(kat1Claims),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=20
    ),
    hashes.SHA256()
)

signatureBlock = SignatureBlock()
certChain = univ.SequenceOf(
            componentType = rfc5280.Certificate(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        )
certChain.append(rsaCert)
signatureBlock['certChain'] = certChain

algIDRsaPSS = rfc5280.AlgorithmIdentifier()
algIDRsaPSS['algorithm'] = rfc8017.id_RSASSA_PSS
pssParams = rfc8017.RSASSA_PSS_params()
algIdSha256 = rfc5280.AlgorithmIdentifier().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
algIdSha256['algorithm'] = rfc8017.id_sha256
pssParams['hashAlgorithm'] = algIdSha256
maskGenAlgId = rfc5280.AlgorithmIdentifier().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
maskGenAlgId['algorithm'] = rfc8017.id_mgf1
pssParams['maskGenAlgorithm'] = maskGenAlgId
# pssParams['saltLength'] = univ.Integer(32) # this seems buggy, and rfc4055.py has a default of 20
algIDRsaPSS['parameters'] = pssParams

signatureBlock['signatureAlgorithm'] = algIDRsaPSS
signatureBlock['signatureValue'] = univ.OctetString(signature)

kat1['signatures'].append(signatureBlock)


print("Outputting KAT1 to example1_kat1.txt")
with open('example1_kat1.txt', 'w') as f:
    f.write(str(kat1))
    f.write("\n")
    f.write("\n")
    f.write("KAT1 DER Base64:\n")
    f.write(base64.b64encode(encode(kat1)).decode('ascii'))





# Construct KAT2 token

# {
#  "keyID": "21",
#  "pubKey": <SPKI>,
#  "keyFingerprintAlg": AlgorithmID(id-sha256),
#  "keyFingerprint": 0xc3b2a1,
#  "purpose": {Decapsulate},
#  "extractable": true,
#  "neverExtractable": false,
#  "imported": true,
# }

kat2 = PkixAttestation()
kat2["version"] = 1

kat2Claims = SetOfClaims()

claim = PkixClaim_keyID()
claim['type'] = id_pkixattest_keyid
claim['value'] = char.IA5String('21')
kat2Claims.append(claim)

claim = PkixClaim_pubKey()
claim['type'] = id_pkixattest_pubKey
claim['value'] = p256SPKI
kat2Claims.append(claim)


claim = PkixClaim_keyFingerprintAlg()
claim['type'] = id_pkixattest_keyFingerprintAlg
algID = rfc5280.AlgorithmIdentifier()
algID['algorithm'] = rfc8017.id_sha256
claim['value'] = algID
kat2Claims.append(claim)

fingerprint = hashlib.sha256(bytes(p256SPKI['subjectPublicKey']))
claim = PkixClaim_keyFingerprint()
claim['type'] = id_pkixattest_keyFingerprint
claim['value'] = univ.OctetString(fingerprint.digest())
kat2Claims.append(claim)

claim = PkixClaim_purpose()
claim['type'] = id_pkixattest_purpose
claim['value'] = PkixClaim_purpose.Value.namedValues['Decapsulate']
kat2Claims.append(claim)

claim = PkixCaim_extractable()
claim['type'] = id_pkixattest_extractable
claim['value'] = univ.Boolean(True)
kat2Claims.append(claim)

claim = PkixClaim_neverExtractable()
claim['type'] = id_pkixattest_neverExtractable
claim['value'] = univ.Boolean(False)
kat2Claims.append(claim)

claim = PkixClaim_imported()
claim['type'] = id_pkixattest_imported
claim['value'] = univ.Boolean(True)
kat2Claims.append(claim)

claim = PkixClaim_nonce()
claim['type'] = id_pkixattest_nonce
claim['value'] = char.IA5String("987654321")
kat2Claims.append(claim)

claim = PkixClaim_attestationTime()
claim['type'] = id_pkixattest_attestationTime
claim['value'] = useful.GeneralizedTime(useful.UTCTime.fromDateTime(datetime.now()))
kat2Claims.append(claim)


kat2['claims'] = kat2Claims
signatures = univ.SequenceOf(
                    componentType = SignatureBlock(),
                    subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
                )


# Sign with the P256 key

hasher = hashes.Hash(hashes.SHA256())
hasher.update(encode(kat2Claims))
digest = hasher.finalize()

signature = p256Privkey.sign(
    digest,
    ec.ECDSA(utils.Prehashed(hashes.SHA256()))
)


signatureBlock = SignatureBlock()
certChain = univ.SequenceOf(
            componentType = rfc5280.Certificate(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        )
certChain.append(p256Cert)
signatureBlock['certChain'] = certChain

algIdP256 = p256SPKI['algorithm']


signatureBlock['signatureAlgorithm'] = algIdP256
signatureBlock['signatureValue'] = univ.OctetString(signature)

kat2['signatures'].append(signatureBlock)




# Construct the PAT



# Construct the example of PkixAttestation as per draft-ounsworth-key-attestation appendix A.2

# {
#   "hwvendor": "IETF RATS",
#   "hwmodel": "RATS HSM 9000",
#   "swversion": "1.2.3",
#   "hwserial": "1234567",
#   "fipsboot": false,
#   nestedTokens: {KAT1, KAT2}
#   "nonce": "987654321",
#   "attestationTime: 2025-01-17-08-33-56
# }

pat = PkixAttestation()
pat["version"] = 1

patClaims = SetOfClaims()

claim = PkixClaim_hwvendor()
claim['type'] = id_pkixattest_hwvendor
claim['value'] = char.UTF8String("IETF RATS")
patClaims.append(claim)

claim = PkixClaim_hwmodel()
claim['type'] = id_pkixattest_hwmodel
claim['value'] = char.UTF8String("RATS HSM 9000")
patClaims.append(claim)

claim = PkixClaim_hwserial()
claim['type'] = id_pkixattest_hwserial
claim['value'] = char.UTF8String("1234567")
patClaims.append(claim)

claim = PkixClaim_fipsboot()
claim['type'] = id_pkixattest_fipsboot
claim['value'] = univ.Boolean(False)
patClaims.append(claim)

claim = PkixClaim_nestedTokens()
claim['type'] = id_pkixattest_nestedTokens
claim['value'] = univ.SequenceOf(
            componentType = PkixAttestation(),
            subtypeSpec = constraint.ValueSizeConstraint(1, MAX)
        )
claim['value'].append(kat1)
claim['value'].append(kat2)
patClaims.append(claim)

claim = PkixClaim_nonce()
claim['type'] = id_pkixattest_nonce
claim['value'] = char.IA5String("987654321")
patClaims.append(claim)

claim = PkixClaim_attestationTime()
claim['type'] = id_pkixattest_attestationTime
claim['value'] = useful.GeneralizedTime(useful.UTCTime.fromDateTime(datetime.now()))
patClaims.append(claim)

pat['claims'].append(patClaims)

# # Compute signatures

# Compute RSA signature
signature = rsaPrivkey.sign(
    encode(kat1Claims),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=20
    ),
    hashes.SHA256()
)

signatureBlock1 = SignatureBlock()
certChain = univ.SequenceOf(
            componentType = rfc5280.Certificate(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        )
certChain.append(rsaCert)
signatureBlock1['certChain'] = certChain

algIDRsaPSS = rfc5280.AlgorithmIdentifier()
algIDRsaPSS['algorithm'] = rfc8017.id_RSASSA_PSS
pssParams = rfc8017.RSASSA_PSS_params()
algIdSha256 = rfc5280.AlgorithmIdentifier().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
algIdSha256['algorithm'] = rfc8017.id_sha256
pssParams['hashAlgorithm'] = algIdSha256
maskGenAlgId = rfc5280.AlgorithmIdentifier().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
maskGenAlgId['algorithm'] = rfc8017.id_mgf1
pssParams['maskGenAlgorithm'] = maskGenAlgId
# pssParams['saltLength'] = univ.Integer(32) # this seems buggy, and rfc4055.py has a default of 20
algIDRsaPSS['parameters'] = pssParams

signatureBlock1['signatureAlgorithm'] = algIDRsaPSS
signatureBlock1['signatureValue'] = univ.OctetString(signature)

pat["signatures"].append(signatureBlock1)

# Compute P256 signature

hasher = hashes.Hash(hashes.SHA256())
hasher.update(encode(kat2Claims))
digest = hasher.finalize()

signature = p256Privkey.sign(
    digest,
    ec.ECDSA(utils.Prehashed(hashes.SHA256()))
)


signatureBlock2 = SignatureBlock()
certChain = univ.SequenceOf(
            componentType = rfc5280.Certificate(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        )
certChain.append(p256Cert)
signatureBlock2['certChain'] = certChain

algIdP256 = p256SPKI['algorithm']


signatureBlock2['signatureAlgorithm'] = algIdP256
signatureBlock2['signatureValue'] = univ.OctetString(signature)

pat['signatures'].append(signatureBlock2)


print("Outputting PAT to example1_pat.txt")
with open('example1_pat.txt', 'w') as f:
    f.write(str(pat))
    f.write("\n")
    f.write("\n")
    f.write("PAT DER Base64:\n")
    f.write(base64.b64encode(encode(pat)).decode('ascii'))


