Evidence:
  TbsEvidence:
    version: 1
    ReportedElement[0]: id-evidence-element-transaction
      Claim[0]: id-evidence-claim-transaction-nonce
              -> [OCTET STRING] deadbeefcafebabe
      Claim[1]: id-evidence-claim-transaction-timestamp
              -> [GeneralizedTime] 20260719125931Z
      Claim[2]: id-evidence-claim-transaction-ak-spki
              -> [OCTET STRING] 3059301306072a8648ce3d02...
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
      signatureValue : 3045022100ea8a3c833988cb...
      keyId          : 4acb3c67cf13bed4048687d6d025267aebc1f267
