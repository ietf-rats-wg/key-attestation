import sys
import argparse
import io

from cryptography import x509
from cryptography.hazmat.primitives import asymmetric, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

import hashlib, base64

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



## Claims

# TODO: define OIDs and ASN.1 for all the EAT claims I'm borrowing.

id_pkixattest_hwserial = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (1,))
class Pkixclaim_hwSerial(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.IA5String())
    )
    type = id_pkixattest_hwserial

    
id_pkixattest_fipsboot = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (2,))
class Pkixclaim_fipsboot(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )
    type = id_pkixattest_fipsboot

id_pkixattest_nestedTokens = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (3,))
class Pkixclaim_nestedTokens(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Sequence(
        componentType = PkixAttestation(),
        subtypeSpec = constraint.ValueSizeConstraint(1, MAX)
        ) )
    )
    type = id_pkixattest_nestedTokens

id_pkixattest_nonce = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (4,))
class Pkixclaim_nonce(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.IA5String())
    )
    type = id_pkixattest_nonce

id_pkixattest_attestationTime = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (5,))
class Pkixclaim_attestationTime(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', useful.GeneralizedTime())
    )
    type = id_pkixattest_attestationTime,

id_pkixattest_keyid = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (6,))
class Pkixclaim_keyID(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', char.IA5String())
    )
    type = id_pkixattest_keyid

id_pkixattest_pubKey = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (7,))
class Pkixclaim_pubKey(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', rfc5280.SubjectPublicKeyInfo())
    )


id_pkixattest_keyFingerprintAlg = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (8,))
class Pkixclaim_keyFingerprintAlg(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', rfc5280.AlgorithmIdentifier())
    )
    type = id_pkixattest_keyFingerprintAlg

id_pkixattest_keyFingerprint = univ.ObjectIdentifier( PKIX_ATTEST_OID_ARC + (9,))
class Pkixclaim_keyFingerprint(PkixClaim):
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

claim = Pkixclaim_keyID()
claim['type'] = id_pkixattest_keyid
claim['value'] = char.IA5String('18')
kat1Claims.append(claim)

claim = Pkixclaim_pubKey()
claim['type'] = id_pkixattest_pubKey
claim['value'] = rsaSPKI
kat1Claims.append(claim)


claim = Pkixclaim_keyFingerprintAlg()
claim['type'] = id_pkixattest_keyFingerprintAlg
algID = rfc5280.AlgorithmIdentifier()
algID['algorithm'] = rfc8017.id_sha256
claim['value'] = algID
kat1Claims.append(claim)


fingerprint = hashlib.sha256(bytes(rsaSPKI['subjectPublicKey']))
claim = Pkixclaim_keyFingerprint()
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


kat1['claims'] = kat1Claims
signatures = univ.SequenceOf(
                    componentType = SignatureBlock(),
                    subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
                )
                                     # create an empty SEQUENCE so that 
                                     # the structure is complete for computing a signature over


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


print("Outputting KAT1 to kat1.txt")
with open('kat1.txt', 'w') as f:
    f.write(str(kat1))
    f.write("\n")
    f.write("\n")
    f.write("KAT1 DER Base64:\n")
    f.write(base64.b64encode(encode(kat1)).decode('ascii'))

# print(kat1)


# TODO - compute a signature with the RSA cert

# kat1Signature = Sign(kat1Claims)
# kat1["signatures"].append(SignatureBlock(...cert..., ...sigAlg, kat1Signature))

# # Encode and output KAT1
# print("Sample KAT token:")
# print(encode(kat1))




# # Construct KAT2 token

# # {
# #  "keyID": "21",
# #  "pubKey": <SPKI>,
# #  "keyFingerprintAlg": AlgorithmID(id-sha256),
# #  "keyFingerprint": 0xc3b2a1,
# #  "purpose": {Decapsulate},
# #  "extractable": true,
# #  "neverExtractable": false,
# #  "imported": true,
# # }

# kat2 = PkixAttestation()
# kat2["version"] = 1

# kat2Claims = SetOfClaims()
# kat2Claims.append(pkixclaim_keyID("21"))
# kat2Claims.append(pkixclaim_pubKey(spkiP256))


# TODO - compute the pub key fingerprint
# fingerprintP256 = ""

# kat2Claims.append(pkixclaim_keyFingerprintAlg(rfc5280.id_sha256))
# kat2Claims.append(pkixclaim_keyFingerprint(fingerprintP256))
# kat2Claims.append(pkixClaim_purpose(pkixClaim_purposes.Decapsulate))
# kat2Claims.append(pkixclaim_extractable(True))
# kat2Claims.append(pkixclaim_neverExtractable(False))
# kat2Claims.append(pkixclaim_imported(True))







# # Construct the example of PkixAttestation as per draft-ounsworth-key-attestation appendix A.2

# # {
# #   "hwvendor": "IETF RATS",
# #   "hwmodel": "RATS HSM 9000",
# #   "swversion": "1.2.3",
# #   "hwserial": "1234567",
# #   "fipsboot": false,
# #   "nonce": "987654321",
# #   "attestationTime: 2025-01-17-08-33-56,
# #   nestedTokens: {KAT1, KAT2}
# # }

# pat = PkixAttestation()
# pat["version"] = 1

# patClaims = SetOfClaims


# # Compute signatures
# TODO
# signature1 = SignatureBlock()

# pat["signatures"].append(signature1)







# # csr_builder.add_attribute(id_aa_evidence_cryptagraphy, evidenceBundles)

# csr = csr_builder.sign(_RSA_DUMMY_KEY, hashes.SHA256())

# # Extract the CertificateRequestInfo (ie throw away the signature)
# cri_der = csr.tbs_certrequest_bytes
# cri_pyasn1, _ = decode(cri_der, rfc2986.CertificationRequestInfo())

# # Add in the evidence attribute.
# cri_pyasn1['attributes'].append(attr_evidence)

# # Swap out the dummy public key for the TPM-controlled one
# pubkey = serialization.load_pem_public_key(args.publickeyfilepem.read())
# pubkey_der = pubkey.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

# spki, _ = decode(pubkey_der, rfc5280.SubjectPublicKeyInfo())
# cri_pyasn1['subjectPKInfo']['subjectPublicKey'] = spki['subjectPublicKey']

# with open('out.cri', 'wb') as f:
#     f.write(encode(cri_pyasn1))

