import sys
import argparse

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import asymmetric, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, utils

import hashlib, base64, binascii
# from ecdsa.util import sigencode_der

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

from pkixattest import *


#  .----------------------------------.
#  | Attester                         |
#  | --------                         |
#  | AK Certs                         |
#  | hwmodel="RATS HSM 9000"          |
#  | fipsboot=true                    |
#  | .----------.  .----------------. |
#  | | Key 18   |  | Key 21         | | 
#  | | RSA      |  | ECDH-P256      | |
#  | |          |  | Partition1     | |
#  | '----------'  '----------------' |
#  '----------------------------------'



# Load the RSA and P256 certs

def loadCertFromPemFile(file):
    idx, substrate = pem.readPemBlocksFromFile(
        open(file, "r"), ('-----BEGIN CERTIFICATE-----',
                    '-----END CERTIFICATE-----')
    )
    if not substrate:
        return None
    
    cert, rest = decode(substrate, asn1Spec=rfc5280.Certificate())

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



# Construct the Attestation-To-Be-Signed


tbsAtt = TbsPkixAttestation()

nonce = b'0102030405'
tbsAtt.addEntity(
        ReportedEntityTransaction()
            .addAttribute( ReportedAttributeTransactionNonce(nonce) )
    )

tbsAtt.addEntity(
        ReportedEntityPlatform()
            .addAttribute( ReportedAttributePlatformSerial("HSM-123") )
            .addAttribute( ReportedAttributePlatformFipsBoot(True) )
            .addAttribute( ReportedAttributePlatformModel("Model ABC") )
            .addAttribute( ReportedAttributePlatformSwVersion("3.1.9") )
    )

tbsAtt.addEntity(
        ReportedEntityKey()
            .addAttribute( ReportedAttributeKeyIdentifier("26d765d8-1afd-4dfb-a290-cf867ddecfa1") )
            .addAttribute( ReportedAttributeKeyExtractable(False) )
            .addAttribute( ReportedAttributeKeySPKI( encode(p256SPKI) ) )
    )

tbsAtt.addEntity(
        ReportedEntityKey()
            .addAttribute( ReportedAttributeKeyIdentifier("49a96ace-e39a-4fd2-bec1-13165a99621c") )
            .addAttribute( ReportedAttributeKeyExtractable(True) )
            .addAttribute( ReportedAttributeKeySPKI( encode(p256SPKI) ) )
    )

# Custom entity and attribute
id_attest_customized = univ.ObjectIdentifier((1, 2, 3, 888))
id_attest_custom_entity_partition = univ.ObjectIdentifier( id_attest_customized + (0,))
id_attest_custom_attribute_partition_identifier = univ.ObjectIdentifier( id_attest_customized + (1,))
tbsAtt.addEntity(
        ReportedEntityGeneric(id_attest_custom_entity_partition)
            .addAttribute( ReportedAttributeString(
                id_attest_custom_attribute_partition_identifier,
                "partition 1"
            )
        )
    )


# RSA SignatureBlock
# # Sign with the RSA key

signature = rsaPrivkey.sign(
    encode(tbsAtt),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=20
    ),
    hashes.SHA256()
)

rsaSignatureBlock = SignatureBlock()
certChain = univ.SequenceOf(
            componentType = rfc5280.Certificate(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        )
certChain.append(rsaCert)
rsaSignatureBlock['certChain'] = certChain

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

rsaSignatureBlock['signatureAlgorithm'] = algIDRsaPSS
rsaSignatureBlock['signatureValue'] = univ.OctetString(signature)



# P256 SignatureBlock
# # Sign with the P256 key

hasher = hashes.Hash(hashes.SHA256())
hasher.update(encode(tbsAtt))
digest = hasher.finalize()

signature = p256Privkey.sign(
    digest,
    ec.ECDSA(utils.Prehashed(hashes.SHA256()))
)


p256SignatureBlock = SignatureBlock()
certChain = univ.SequenceOf(
            componentType = rfc5280.Certificate(),
            subtypeSpec = constraint.ValueSizeConstraint(0, MAX)
        )
certChain.append(p256Cert)
p256SignatureBlock['certChain'] = certChain

algIdP256 = p256SPKI['algorithm']


p256SignatureBlock['signatureAlgorithm'] = algIdP256
p256SignatureBlock['signatureValue'] = univ.OctetString(signature)





# Assemble the outer object with signatures

fullAtt = PkixAttestation()
fullAtt['tbs'] = tbsAtt
fullAtt['signatures'].append(rsaSignatureBlock)
fullAtt['signatures'].append(p256SignatureBlock)
print(fullAtt)

derAttMsg = encode(fullAtt)
hexDerAttMsg = binascii.hexlify(derAttMsg)
print(hexDerAttMsg)



print("Outputting to sample.txt")
with open('sample1.txt', 'w') as f:
    f.write(str(fullAtt))
    f.write("\n")
    f.write("\n")
    f.write("DER Base64:\n")
    f.write(base64.b64encode(encode(fullAtt)).decode('ascii'))


