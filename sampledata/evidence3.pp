Evidence:
  TbsEvidence:
    version: 1
    ReportedEntity[0]: id-evidence-entity-transaction
      Claim[0]: id-evidence-claim-transaction-nonce
              -> [bytes] cafebabedeadbeef
      Claim[1]: id-evidence-claim-transaction-timestamp
              -> [time] 20250314120000Z
      Claim[2]: id-evidence-claim-transaction-ak-spki
              -> [bytes] 3059301306072a8648ce3d02...
      Claim[3]: id-evidence-claim-transaction-ak-spki
              -> [bytes] 3059301306072a8648ce3d02...
    ReportedEntity[1]: id-evidence-entity-platform
      Claim[0]: id-evidence-claim-platform-hwmodel
              -> [utf8String] HSM-9000
      Claim[1]: id-evidence-claim-platform-hwserial
              -> [utf8String] 17-a1b2
    ReportedEntity[2]: id-evidence-entity-platform
      Claim[0]: id-evidence-claim-platform-vendor
              -> [utf8String] BigCloudCorp Tenant Management System
      Claim[1]: id-evidence-claim-platform-swname
              -> [utf8String] tenant-001
    ReportedEntity[3]: id-evidence-entity-key
      Claim[0]: id-evidence-claim-key-identifier
              -> [utf8String] key-001
      Claim[1]: id-evidence-claim-key-spki
              -> [bytes] 3059301306072a8648ce3d02...
      Claim[2]: id-evidence-claim-key-extractable
              -> [bool] False
      Claim[3]: id-evidence-claim-key-never-extractable
              -> [bool] True
      Claim[4]: id-evidence-claim-key-sensitive
              -> [bool] True
      Claim[5]: id-evidence-claim-key-local
              -> [bool] True
      Claim[6]: id-evidence-claim-key-purpose
              -> [bytes] 301806062a03876702040606...
  Signatures (2):
    SignatureBlock[0]:
      algorithm      : 1.2.840.10045.4.3.2
      signatureValue : 304402201848fc67aa9eacd6...
      AK Certificate : present
    SignatureBlock[1]:
      algorithm      : 1.2.840.10045.4.3.2
      signatureValue : 30460221008b88e8ccd08f85...
      AK Certificate : present
  Intermediate Certificates:  (2)
