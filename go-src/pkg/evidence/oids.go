package evidence

import "encoding/asn1"

var (
	OIDPkixEvidence = asn1.ObjectIdentifier{1, 2, 3, 999}

	OIDEntityType          = asn1.ObjectIdentifier{1, 2, 3, 999, 0}
	OIDEntityTransaction   = asn1.ObjectIdentifier{1, 2, 3, 999, 0, 0}
	OIDEntityPlatform      = asn1.ObjectIdentifier{1, 2, 3, 999, 0, 1}
	OIDEntityKey           = asn1.ObjectIdentifier{1, 2, 3, 999, 0, 2}

	OIDClaimType                 = asn1.ObjectIdentifier{1, 2, 3, 999, 1}
	OIDClaimTransaction          = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 0}
	OIDClaimTransactionNonce     = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 0, 0}
	OIDClaimTransactionTimestamp = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 0, 1}
	OIDClaimTransactionAKSPKI    = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 0, 2}

	OIDClaimPlatform           = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1}
	OIDClaimPlatformVendor     = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 0}
	OIDClaimPlatformOemID      = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 1}
	OIDClaimPlatformHWModel    = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 2}
	OIDClaimPlatformHWVersion  = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 3}
	OIDClaimPlatformHWSerial   = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 4}
	OIDClaimPlatformSWName     = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 5}
	OIDClaimPlatformSWVersion  = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 6}
	OIDClaimPlatformDebugStat  = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 7}
	OIDClaimPlatformUptime     = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 8}
	OIDClaimPlatformBootCount  = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 9}
	OIDClaimPlatformUserMods   = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 10}
	OIDClaimPlatformFIPSBoot   = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 11}
	OIDClaimPlatformFIPSVer    = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 12}
	OIDClaimPlatformFIPSLevel  = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 13}
	OIDClaimPlatformFIPSModule = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 1, 14}

	OIDClaimKey                   = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 2}
	OIDClaimKeyIdentifier          = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 2, 0}
	OIDClaimKeySPKI                = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 2, 1}
	OIDClaimKeyExtractable         = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 2, 2}
	OIDClaimKeySensitive           = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 2, 3}
	OIDClaimKeyNeverExtractable    = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 2, 4}
	OIDClaimKeyLocal               = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 2, 5}
	OIDClaimKeyExpiry              = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 2, 6}
	OIDClaimKeyPurpose             = asn1.ObjectIdentifier{1, 2, 3, 999, 1, 2, 7}

	OIDKeyCapability            = asn1.ObjectIdentifier{1, 2, 3, 999, 2}
	OIDKeyCapabilityEncrypt     = asn1.ObjectIdentifier{1, 2, 3, 999, 2, 0}
	OIDKeyCapabilityDecrypt     = asn1.ObjectIdentifier{1, 2, 3, 999, 2, 1}
	OIDKeyCapabilityWrap        = asn1.ObjectIdentifier{1, 2, 3, 999, 2, 2}
	OIDKeyCapabilityUnwrap      = asn1.ObjectIdentifier{1, 2, 3, 999, 2, 3}
	OIDKeyCapabilitySign        = asn1.ObjectIdentifier{1, 2, 3, 999, 2, 4}
	OIDKeyCapabilitySignRecover = asn1.ObjectIdentifier{1, 2, 3, 999, 2, 5}
	OIDKeyCapabilityVerify      = asn1.ObjectIdentifier{1, 2, 3, 999, 2, 6}
	OIDKeyCapabilityVerifyRecover = asn1.ObjectIdentifier{1, 2, 3, 999, 2, 7}
	OIDKeyCapabilityDerive       = asn1.ObjectIdentifier{1, 2, 3, 999, 2, 8}
)

type ClaimSpec struct {
	Name        string
	ValueKind   string
	Multiple    bool
	EntityType  asn1.ObjectIdentifier
}

var EntityTypeNames = map[string]string{
	OIDEntityTransaction.String(): "transaction",
	OIDEntityPlatform.String():    "platform",
	OIDEntityKey.String():         "key",
}

var ClaimSpecs = map[string]ClaimSpec{
	OIDClaimTransactionNonce.String():     {Name: "nonce", ValueKind: "bytes", Multiple: false, EntityType: OIDEntityTransaction},
	OIDClaimTransactionTimestamp.String(): {Name: "timestamp", ValueKind: "time", Multiple: false, EntityType: OIDEntityTransaction},
	OIDClaimTransactionAKSPKI.String():    {Name: "ak-spki", ValueKind: "bytes", Multiple: true, EntityType: OIDEntityTransaction},

	OIDClaimPlatformVendor.String():     {Name: "vendor", ValueKind: "utf8String", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformOemID.String():      {Name: "oemid", ValueKind: "bytes", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformHWModel.String():    {Name: "hwmodel", ValueKind: "bytes", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformHWVersion.String():  {Name: "hwversion", ValueKind: "utf8String", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformHWSerial.String():   {Name: "hwserial", ValueKind: "utf8String", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformSWName.String():     {Name: "swname", ValueKind: "utf8String", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformSWVersion.String():  {Name: "swversion", ValueKind: "utf8String", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformDebugStat.String():  {Name: "dbgstat", ValueKind: "int", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformUptime.String():     {Name: "uptime", ValueKind: "int", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformBootCount.String():  {Name: "bootcount", ValueKind: "int", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformUserMods.String():   {Name: "usermods", ValueKind: "bytes", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformFIPSBoot.String():   {Name: "fipsboot", ValueKind: "bool", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformFIPSVer.String():    {Name: "fipsver", ValueKind: "utf8String", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformFIPSLevel.String():  {Name: "fipslevel", ValueKind: "int", Multiple: false, EntityType: OIDEntityPlatform},
	OIDClaimPlatformFIPSModule.String(): {Name: "fipsmodule", ValueKind: "utf8String", Multiple: false, EntityType: OIDEntityPlatform},

	OIDClaimKeyIdentifier.String():       {Name: "identifier", ValueKind: "utf8String", Multiple: true, EntityType: OIDEntityKey},
	OIDClaimKeySPKI.String():             {Name: "spki", ValueKind: "bytes", Multiple: false, EntityType: OIDEntityKey},
	OIDClaimKeyExtractable.String():      {Name: "extractable", ValueKind: "bool", Multiple: false, EntityType: OIDEntityKey},
	OIDClaimKeySensitive.String():        {Name: "sensitive", ValueKind: "bool", Multiple: false, EntityType: OIDEntityKey},
	OIDClaimKeyNeverExtractable.String(): {Name: "never-extractable", ValueKind: "bool", Multiple: false, EntityType: OIDEntityKey},
	OIDClaimKeyLocal.String():            {Name: "local", ValueKind: "bool", Multiple: false, EntityType: OIDEntityKey},
	OIDClaimKeyExpiry.String():           {Name: "expiry", ValueKind: "time", Multiple: false, EntityType: OIDEntityKey},
	OIDClaimKeyPurpose.String():          {Name: "purpose", ValueKind: "bytes", Multiple: false, EntityType: OIDEntityKey},
}

var KeyCapabilityNames = map[string]string{
	OIDKeyCapabilityEncrypt.String():      "encrypt",
	OIDKeyCapabilityDecrypt.String():      "decrypt",
	OIDKeyCapabilityWrap.String():         "wrap",
	OIDKeyCapabilityUnwrap.String():       "unwrap",
	OIDKeyCapabilitySign.String():         "sign",
	OIDKeyCapabilitySignRecover.String():  "sign-recover",
	OIDKeyCapabilityVerify.String():       "verify",
	OIDKeyCapabilityVerifyRecover.String(): "verify-recover",
	OIDKeyCapabilityDerive.String():       "derive",
}
