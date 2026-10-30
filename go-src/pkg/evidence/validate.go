package evidence

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

func Validate(e *Evidence) []error {
	var errs []error
	if len(e.Signatures) == 0 {
		errs = append(errs, fmt.Errorf("evidence must contain at least one signature"))
	}
	if len(e.TBS.ReportedElements) == 0 {
		errs = append(errs, fmt.Errorf("tbs must contain at least one element"))
	}
	for _, sig := range e.Signatures {
		if sig.SID.KeyID == nil && !hasRawValue(sig.SID.Certificate) && !hasRawValue(sig.SID.SubjectPublicKeyInfo) {
			errs = append(errs, fmt.Errorf("empty SignerIdentifier"))
		}
	}
	if e.TBS.Version != 1 {
		errs = append(errs, fmt.Errorf("tbs.version must be 1, got %d", e.TBS.Version))
	}

	elementCount := map[string]int{}
	for _, element := range e.TBS.ReportedElements {
		elementCount[element.ElementType.String()]++
		if len(element.Claims) == 0 {
			errs = append(errs, fmt.Errorf("element must contain at least one claim"))
		}
		claimCount := map[string]int{}
		for _, claim := range element.Claims {
			claimCount[claim.ClaimType.String()]++
			if spec, ok := ClaimSpecs[claim.ClaimType.String()]; ok && !spec.Multiple && claimCount[claim.ClaimType.String()] > 1 {
				errs = append(errs, fmt.Errorf("claim %s appears multiple times in element %s", spec.Name, element.ElementType.String()))
			}
			errs = append(errs, validateClaim(element.ElementType, claim)...)
		}
	}

	if elementCount[OIDElementPlatform.String()] > 1 {
		errs = append(errs, fmt.Errorf("platform element appears %d times", elementCount[OIDElementPlatform.String()]))
	}
	if elementCount[OIDElementTransaction.String()] > 1 {
		errs = append(errs, fmt.Errorf("transaction element appears %d times", elementCount[OIDElementTransaction.String()]))
	}

	keyIDs := map[string]int{}
	for index, element := range e.TBS.ReportedElements {
		if !element.ElementType.Equal(OIDElementKey) {
			continue
		}
		ids := collectIdentifiers(element)
		if len(ids) == 0 {
			errs = append(errs, fmt.Errorf("key element missing identifier claim"))
			continue
		}
		for _, id := range ids {
			if previous, ok := keyIDs[id]; ok && previous != index {
				errs = append(errs, fmt.Errorf("duplicate key identifier %q across key elements", id))
			}
			keyIDs[id] = index
		}
	}

	errs = append(errs, validateFIPSLevel(e)...)
	errs = append(errs, validateCCEALLevel(e)...)
	errs = append(errs, validateDeviceBound(e)...)
	errs = append(errs, validateAKSPKIUniqueness(e)...)

	return errs
}

func validateClaim(elementTypeOID asn1.ObjectIdentifier, claim ReportedClaim) []error {
	if !hasRawValue(claim.Value) {
		return []error{fmt.Errorf("claim %s is missing a value", claim.ClaimType)}
	}
	spec, ok := ClaimSpecs[claim.ClaimType.String()]
	if !ok {
		return nil
	}

	var errs []error
	if !spec.ElementType.Equal(elementTypeOID) {
		errs = append(errs, fmt.Errorf("claim %s is not valid for element %s", spec.Name, elementTypeOID.String()))
	}

	cv, err := DecodeClaimValueFor(claim.ClaimType, claim.Value)
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid %s claim encoding: %v", spec.Name, err))
		return errs
	}
	if cv.Kind == "absent" {
		errs = append(errs, fmt.Errorf("claim %s is missing a value", spec.Name))
		return errs
	}
	if cv.Kind != spec.ValueKind {
		errs = append(errs, fmt.Errorf("claim %s must be %s, got %s", spec.Name, spec.ValueKind, cv.Kind))
		return errs
	}

	switch {
	case claim.ClaimType.Equal(OIDClaimKeySPKI), claim.ClaimType.Equal(OIDClaimTransactionAKSPKI):
		if err := validateSPKI(cv.Bytes); err != nil {
			errs = append(errs, fmt.Errorf("claim %s must contain a DER SubjectPublicKeyInfo: %v", spec.Name, err))
		}
	case claim.ClaimType.Equal(OIDClaimKeyPurpose):
		if _, err := DecodeCapabilities(cv.Bytes); err != nil {
			errs = append(errs, fmt.Errorf("claim %s must contain KeyPurposes: %v", spec.Name, err))
		}
	}

	return errs
}

func collectIdentifiers(element ReportedElement) []string {
	var ids []string
	for _, claim := range element.Claims {
		if !claim.ClaimType.Equal(OIDClaimKeyIdentifier) {
			continue
		}
		cv, err := DecodeClaimValue(claim.Value)
		if err != nil {
			continue
		}
		if cv.Kind == "utf8String" {
			ids = append(ids, cv.String)
		}
	}
	return ids
}

func validateFIPSLevel(e *Evidence) []error {
	var errs []error
	for _, element := range e.TBS.ReportedElements {
		if !element.ElementType.Equal(OIDElementPlatform) {
			continue
		}
		for _, claim := range element.Claims {
			if !claim.ClaimType.Equal(OIDClaimPlatformFIPSLevel) {
				continue
			}
			cv, err := DecodeClaimValue(claim.Value)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid fipslevel claim encoding: %v", err))
				continue
			}
			if cv.Kind != "int" {
				errs = append(errs, fmt.Errorf("fipslevel claim must be int, got %s", cv.Kind))
				continue
			}
			if cv.Integer == nil || !cv.Integer.IsInt64() || cv.Int < 1 || cv.Int > 4 {
				errs = append(errs, fmt.Errorf("fipslevel must be in range 1..4, got %d", cv.Int))
			}
		}
	}
	return errs
}

// ccEALSchemes lists the Common Criteria schemes whose cceallevel claim must follow the EAL syntax.
var ccEALSchemes = []string{"ISO15408", "CCRA", "EUCC"}

var ccEALPattern = regexp.MustCompile(`^EAL[1-7](\+[A-Z]{3}_[A-Z]{3}\.[0-9]+(,[A-Z]{3}_[A-Z]{3}\.[0-9]+)*)?$`)

func validateCCEALLevel(e *Evidence) []error {
	var errs []error
	for _, element := range e.TBS.ReportedElements {
		if !element.ElementType.Equal(OIDElementPlatform) {
			continue
		}
		var scheme, eal *ClaimValue
		for _, claim := range element.Claims {
			if !claim.ClaimType.Equal(OIDClaimPlatformCCScheme) && !claim.ClaimType.Equal(OIDClaimPlatformCCEALLevel) {
				continue
			}
			cv, err := DecodeClaimValue(claim.Value)
			if err != nil || cv.Kind != "utf8String" {
				continue // reported by validateClaim
			}
			if claim.ClaimType.Equal(OIDClaimPlatformCCScheme) {
				scheme = &cv
			} else {
				eal = &cv
			}
		}
		if scheme == nil || eal == nil || !hasCCEALScheme(scheme.String) {
			continue
		}
		if !ccEALPattern.MatchString(eal.String) {
			errs = append(errs, fmt.Errorf("cceallevel %q does not follow the EAL syntax", eal.String))
		}
	}
	return errs
}

func hasCCEALScheme(scheme string) bool {
	for _, prefix := range ccEALSchemes {
		if strings.HasPrefix(scheme, prefix) {
			return true
		}
	}
	return false
}

// deviceBoundImplies lists the key claim values implied by device-bound = TRUE.
var deviceBoundImplies = []struct {
	oid      asn1.ObjectIdentifier
	expected bool
}{
	{OIDClaimKeyLocal, true},
	{OIDClaimKeyExtractable, false},
	{OIDClaimKeyNeverExtractable, true},
}

func validateDeviceBound(e *Evidence) []error {
	var errs []error
	for _, element := range e.TBS.ReportedElements {
		if !element.ElementType.Equal(OIDElementKey) {
			continue
		}
		values := map[string]bool{}
		for _, claim := range element.Claims {
			cv, err := DecodeClaimValue(claim.Value)
			if err != nil || cv.Kind != "bool" {
				continue // reported by validateClaim
			}
			values[claim.ClaimType.String()] = cv.Bool
		}
		if !values[OIDClaimKeyDeviceBound.String()] {
			continue
		}
		for _, implied := range deviceBoundImplies {
			if value, ok := values[implied.oid.String()]; ok && value != implied.expected {
				errs = append(errs, fmt.Errorf("device-bound contradicts claim %s", ClaimSpecs[implied.oid.String()].Name))
			}
		}
	}
	return errs
}

func validateAKSPKIUniqueness(e *Evidence) []error {
	var errs []error
	seen := map[string]struct{}{}
	for _, element := range e.TBS.ReportedElements {
		if !element.ElementType.Equal(OIDElementTransaction) {
			continue
		}
		for _, claim := range element.Claims {
			if !claim.ClaimType.Equal(OIDClaimTransactionAKSPKI) {
				continue
			}
			cv, err := DecodeClaimValueFor(claim.ClaimType, claim.Value)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid ak-spki claim encoding: %v", err))
				continue
			}
			if cv.Kind != "spki" {
				errs = append(errs, fmt.Errorf("ak-spki claim must be spki, got %s", cv.Kind))
				continue
			}
			keyBytes := cv.Bytes
			if key, err := x509.ParsePKIXPublicKey(keyBytes); err == nil {
				if canonical, err := x509.MarshalPKIXPublicKey(key); err == nil {
					keyBytes = canonical
				}
			}
			k := base64.StdEncoding.EncodeToString(keyBytes)
			if _, ok := seen[k]; ok {
				errs = append(errs, fmt.Errorf("ak-spki claim repeated with identical key material"))
			}
			seen[k] = struct{}{}
		}
	}
	return errs
}
