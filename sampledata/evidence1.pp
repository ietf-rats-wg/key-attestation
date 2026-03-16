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
              -> [bytes] 48534d2d39303030
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
      signatureValue : 3046022100b5636293faa29f...
      keyId          : 61c1886abaacb48ba275116780ecd4f4e61815ee
