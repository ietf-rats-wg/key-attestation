package evidence

import "encoding/asn1"

// OIDs use 999 as a temporary substitute for the draft's TBD assignments.
var (
	OIDAttestationKey           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 999}
	OIDKeyCapabilityDecapsulate = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 9}
	OIDKeyCapabilityEncapsulate = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 10}
	OIDPkixEvidence             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999}

	OIDElementType        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 0}
	OIDElementTransaction = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 0, 0}
	OIDElementPlatform    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 0, 1}
	OIDElementKey         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 0, 2}

	OIDClaimType                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1}
	OIDClaimTransaction          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 0}
	OIDClaimTransactionNonce     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 0, 0}
	OIDClaimTransactionTimestamp = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 0, 1}
	OIDClaimTransactionAKSPKI    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 0, 2}

	OIDClaimPlatform           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1}
	OIDClaimPlatformVendor     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 0}
	OIDClaimPlatformOemID      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 1}
	OIDClaimPlatformHWModel    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 2}
	OIDClaimPlatformHWVersion  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 3}
	OIDClaimPlatformHWSerial   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 4}
	OIDClaimPlatformSWName     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 5}
	OIDClaimPlatformSWVersion  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 6}
	OIDClaimPlatformDebugStat  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 7}
	OIDClaimPlatformUptime     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 8}
	OIDClaimPlatformBootCount  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 9}
	OIDClaimPlatformFIPSBoot   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 10}
	OIDClaimPlatformFIPSVer    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 11}
	OIDClaimPlatformFIPSLevel  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 12}
	OIDClaimPlatformFIPSModule = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 1, 13}

	OIDClaimKey                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 2}
	OIDClaimKeyIdentifier       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 2, 0}
	OIDClaimKeySPKI             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 2, 1}
	OIDClaimKeyExtractable      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 2, 2}
	OIDClaimKeySensitive        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 2, 3}
	OIDClaimKeyNeverExtractable = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 2, 4}
	OIDClaimKeyLocal            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 2, 5}
	OIDClaimKeyExpiry           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 2, 6}
	OIDClaimKeyPurpose          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 1, 2, 7}

	OIDKeyCapability              = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2}
	OIDKeyCapabilityEncrypt       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 0}
	OIDKeyCapabilityDecrypt       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 1}
	OIDKeyCapabilityWrap          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 2}
	OIDKeyCapabilityUnwrap        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 3}
	OIDKeyCapabilitySign          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 4}
	OIDKeyCapabilitySignRecover   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 5}
	OIDKeyCapabilityVerify        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 6}
	OIDKeyCapabilityVerifyRecover = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 7}
	OIDKeyCapabilityDerive        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 999, 2, 8}
)

type ClaimSpec struct {
	Name        string
	ValueKind   string
	Multiple    bool
	ElementType asn1.ObjectIdentifier
}

var ElementTypeNames = map[string]string{
	OIDElementTransaction.String(): "transaction",
	OIDElementPlatform.String():    "platform",
	OIDElementKey.String():         "key",
}

var ClaimSpecs = map[string]ClaimSpec{
	OIDClaimTransactionNonce.String():     {Name: "nonce", ValueKind: "bytes", Multiple: false, ElementType: OIDElementTransaction},
	OIDClaimTransactionTimestamp.String(): {Name: "timestamp", ValueKind: "time", Multiple: false, ElementType: OIDElementTransaction},
	OIDClaimTransactionAKSPKI.String():    {Name: "ak-spki", ValueKind: "bytes", Multiple: true, ElementType: OIDElementTransaction},

	OIDClaimPlatformVendor.String():     {Name: "vendor", ValueKind: "utf8String", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformOemID.String():      {Name: "oemid", ValueKind: "bytes", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformHWModel.String():    {Name: "hwmodel", ValueKind: "bytes", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformHWVersion.String():  {Name: "hwversion", ValueKind: "utf8String", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformHWSerial.String():   {Name: "hwserial", ValueKind: "utf8String", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformSWName.String():     {Name: "swname", ValueKind: "utf8String", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformSWVersion.String():  {Name: "swversion", ValueKind: "utf8String", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformDebugStat.String():  {Name: "dbgstat", ValueKind: "int", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformUptime.String():     {Name: "uptime", ValueKind: "int", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformBootCount.String():  {Name: "bootcount", ValueKind: "int", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformFIPSBoot.String():   {Name: "fipsboot", ValueKind: "bool", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformFIPSVer.String():    {Name: "fipsver", ValueKind: "utf8String", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformFIPSLevel.String():  {Name: "fipslevel", ValueKind: "int", Multiple: false, ElementType: OIDElementPlatform},
	OIDClaimPlatformFIPSModule.String(): {Name: "fipsmodule", ValueKind: "utf8String", Multiple: false, ElementType: OIDElementPlatform},

	OIDClaimKeyIdentifier.String():       {Name: "identifier", ValueKind: "utf8String", Multiple: true, ElementType: OIDElementKey},
	OIDClaimKeySPKI.String():             {Name: "spki", ValueKind: "bytes", Multiple: false, ElementType: OIDElementKey},
	OIDClaimKeyExtractable.String():      {Name: "extractable", ValueKind: "bool", Multiple: false, ElementType: OIDElementKey},
	OIDClaimKeySensitive.String():        {Name: "sensitive", ValueKind: "bool", Multiple: false, ElementType: OIDElementKey},
	OIDClaimKeyNeverExtractable.String(): {Name: "never-extractable", ValueKind: "bool", Multiple: false, ElementType: OIDElementKey},
	OIDClaimKeyLocal.String():            {Name: "local", ValueKind: "bool", Multiple: false, ElementType: OIDElementKey},
	OIDClaimKeyExpiry.String():           {Name: "expiry", ValueKind: "time", Multiple: false, ElementType: OIDElementKey},
	OIDClaimKeyPurpose.String():          {Name: "purpose", ValueKind: "purposes", Multiple: false, ElementType: OIDElementKey},
}

var KeyCapabilityNames = map[string]string{
	OIDKeyCapabilityDecapsulate.String():   "decapsulate",
	OIDKeyCapabilityEncapsulate.String():   "encapsulate",
	OIDKeyCapabilityEncrypt.String():       "encrypt",
	OIDKeyCapabilityDecrypt.String():       "decrypt",
	OIDKeyCapabilityWrap.String():          "wrap",
	OIDKeyCapabilityUnwrap.String():        "unwrap",
	OIDKeyCapabilitySign.String():          "sign",
	OIDKeyCapabilitySignRecover.String():   "sign-recover",
	OIDKeyCapabilityVerify.String():        "verify",
	OIDKeyCapabilityVerifyRecover.String(): "verify-recover",
	OIDKeyCapabilityDerive.String():        "derive",
}
