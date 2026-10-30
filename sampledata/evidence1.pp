Evidence:
  TbsEvidence:
    version: 1
    ReportedElement[0]: id-evidence-element-transaction
      Claim[0]: id-evidence-claim-transaction-nonce
              -> [OCTET STRING] deadbeefcafebabe
      Claim[1]: id-evidence-claim-transaction-timestamp
              -> [GeneralizedTime] 20261030172826Z
      Claim[2]: id-evidence-claim-transaction-ak-spki
              -> [SubjectPublicKeyInfo] 3059301306072a8648ce3d02...
    ReportedElement[1]: id-evidence-element-platform
      Claim[0]: id-evidence-claim-platform-vendor
              -> [UTF8String] Acme Corp
      Claim[1]: id-evidence-claim-platform-hwmodel
              -> [OCTET STRING] 48534d2d39303030
      Claim[2]: id-evidence-claim-platform-hwversion
              -> [UTF8String] 2.1.0
      Claim[3]: id-evidence-claim-platform-fipsboot
              -> [BOOLEAN] True
      Claim[4]: id-evidence-claim-platform-fipslevel
              -> [INTEGER] 3
      Claim[5]: id-evidence-claim-platform-uptime
              -> [INTEGER] 86400
  Signatures (1):
    SignatureBlock[0]:
      algorithm      : 1.2.840.10045.4.3.2
      signatureValue : 3044022044a79158010aa2e1...
      keyId          : e8ec8f23b61e50cb5c21241cd5e816e1e9176e0e
  Intermediate Certificates:  (1)
