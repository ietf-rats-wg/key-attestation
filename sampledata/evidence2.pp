Evidence:
  TbsEvidence:
    version: 1
    ReportedElement[0]: id-evidence-element-transaction
      Claim[0]: id-evidence-claim-transaction-nonce
              -> [OCTET STRING] beefcafebabedead
      Claim[1]: id-evidence-claim-transaction-timestamp
              -> [GeneralizedTime] 20260719125931Z
      Claim[2]: id-evidence-claim-transaction-ak-spki
              -> [OCTET STRING] 3059301306072a8648ce3d02...
    ReportedElement[1]: id-evidence-element-platform
      Claim[0]: id-evidence-claim-platform-hwmodel
              -> [OCTET STRING] 48534d2d39303030
    ReportedElement[2]: id-evidence-element-key
      Claim[0]: id-evidence-claim-key-identifier
              -> [UTF8String] 9a25f603-a2c4-4dad-9ee0-...
      Claim[1]: id-evidence-claim-key-spki
              -> [OCTET STRING] 3059301306072a8648ce3d02...
      Claim[2]: id-evidence-claim-key-extractable
              -> [BOOLEAN] False
      Claim[3]: id-evidence-claim-key-never-extractable
              -> [BOOLEAN] True
      Claim[4]: id-evidence-claim-key-sensitive
              -> [BOOLEAN] True
      Claim[5]: id-evidence-claim-key-local
              -> [BOOLEAN] True
      Claim[6]: id-evidence-claim-key-purpose
              -> [KeyPurposes] id-evidence-key-capability-sign
    ReportedElement[3]: id-evidence-element-key
      Claim[0]: id-evidence-claim-key-identifier
              -> [UTF8String] 85704b99-7097-4bca-93b6-...
      Claim[1]: id-evidence-claim-key-spki
              -> [OCTET STRING] 3059301306072a8648ce3d02...
      Claim[2]: id-evidence-claim-key-extractable
              -> [BOOLEAN] True
      Claim[3]: id-evidence-claim-key-sensitive
              -> [BOOLEAN] False
  Signatures (1):
    SignatureBlock[0]:
      algorithm      : 1.2.840.10045.4.3.2
      signatureValue : 3045022100c435d09544c77d...
      AK Certificate : present
  Intermediate Certificates:  (1)
