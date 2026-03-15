Evidence:
  TbsEvidence:
    version: 1
    ReportedEntity[0]: id-evidence-entity-transaction
      Claim[0]: id-evidence-claim-transaction-nonce
              -> [bytes] deadbeefcafebabe
      Claim[1]: id-evidence-claim-transaction-timestamp
              -> [time] 20250314120000Z
      Claim[2]: id-evidence-claim-transaction-ak-spki
              -> [bytes] 3059301306072a8648ce3d02...
    ReportedEntity[1]: id-evidence-entity-platform
      Claim[0]: id-evidence-claim-platform-vendor
              -> [utf8String] Acme Corp
      Claim[1]: id-evidence-claim-platform-hwmodel
              -> [utf8String] HSM-9000
      Claim[2]: id-evidence-claim-platform-hwversion
              -> [utf8String] 2.1.0
      Claim[3]: id-evidence-claim-platform-fipsboot
              -> [bool] True
      Claim[4]: id-evidence-claim-platform-fipslevel
              -> [int] 3
      Claim[5]: id-evidence-claim-platform-uptime
              -> [int] 86400
  Signatures (1):
    SignatureBlock[0]:
      algorithm      : 1.2.840.10045.4.3.2
      signatureValue : 304402200ffddfed48cfd25a...
      keyId          : 3c193b92c7f3f4a5f7d791bbd5e1329e75724de8
