import sys
import argparse
import io

from cryptography import x509
from cryptography.hazmat.primitives import asymmetric, serialization, hashes

from pyasn1.type import univ, char, namedtype, constraint
from pyasn1.codec.der import decoder 
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

from pyasn1_modules import pem
from pyasn1.type import namedval
from pyasn1.type import useful
from pyasn1_alt_modules import rfc2986, rfc5280, rfc5751, rfc8017


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
        namedtype.NamedType("certChain", univ.Integer()),
        namedtype.NamedType("signatureAlgorithm", rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType("signatureValue", univ.OctetString())
    )

# SetOfClaims ::= SEQUENCE OF TypeAndValue -- TODO look up the built-in type.
class SetOfClaims(univ.SequenceOf):
    componentType = PkixClaim(),
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
class Pkixclaim_keyID(PkixClaim):
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
class pkixclaim_extractable(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )
    type = id_pkixattest_extractable

id_pkixattest_neverExtractable = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (12,))
class pkixclaim_neverExtractable(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )
    type = id_pkixattest_neverExtractable

id_pkixattest_imported = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (13,))
class pkixclaim_imported(univ.Boolean):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Boolean())
    )
    type = id_pkixattest_imported

id_pkixattest_keyexpiry = univ.ObjectIdentifier(PKIX_ATTEST_OID_ARC + (14,))
class pkixclaim_keyExpiry(PkixClaim):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', useful.GeneralizedTime())
    )
    type = id_pkixattest_imported


# # Load the RSA and P256 certs

# # Extract the pub key from the RSA and P256 certs

# TODO -- this is busted

# pubkeyRsa = serialization.load_pem_public_key("rfc9500_rsa.crt")
# pubkeyRSA_der = pubkey.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
# spkiRSA, _ = decode(pubkey_der, rfc5280.SubjectPublicKeyInfo())

# #... ditto for P256

# spkiP256 = ""




# # Construct KAT1 token

# # {
# #   "keyID": "18",
# #   "pubKey": <SPKI>,
# #   "keyFingerprintAlg": AlgorithmID(id-sha256),
# #   "keyFingerprint": 0x1a2b3c,
# #   "purpose": {Sign},
# #   "extractable": true,
# #   "neverExtractable": false,
# #   "imported": false
# # }

# kat1 = PkixAttestation()
# kat1["version"] = 1

# kat1Claims = SetOfClaims()
# kat1Claims.append(pkixclaim_keyID("18"))
# kat1Claims.append(pkixclaim_pubKey(spkiRSA))


# TODO - compute the pub key fingerprint
# fingerprintRSA = ""

# kat1Claims.append(pkixclaim_keyFingerprintAlg(rfc5280.id_sha256))
# kat1Claims.append(pkixclaim_keyFingerprint(fingerprintRSA))
# kat1Claims.append(pkixClaim_purpose(pkixClaim_purposes.Sign))
# kat1Claims.append(pkixclaim_extractable(True))
# kat1Claims.append(pkixclaim_neverExtractable(False))
# kat1Claims.append(pkixclaim_imported(False))


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
# #   "hwmodel": "HSM 9000",
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
