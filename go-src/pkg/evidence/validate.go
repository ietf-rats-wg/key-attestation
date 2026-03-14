package evidence

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
)

func Validate(e *Evidence) []error {
	var errs []error
	if e.TBS.Version != 1 {
		errs = append(errs, fmt.Errorf("tbs.version must be 1, got %d", e.TBS.Version))
	}

	entityCount := map[string]int{}
	for _, entity := range e.TBS.ReportedEntities {
		entityCount[entity.EntityType.String()]++
		claimCount := map[string]int{}
		for _, claim := range entity.ClaimSet {
			claimCount[claim.ClaimType.String()]++
			if spec, ok := ClaimSpecs[claim.ClaimType.String()]; ok && !spec.Multiple && claimCount[claim.ClaimType.String()] > 1 {
				errs = append(errs, fmt.Errorf("claim %s appears multiple times in entity %s", spec.Name, entity.EntityType.String()))
			}
			errs = append(errs, validateClaim(entity.EntityType, claim)...)
		}
	}

	if entityCount[OIDEntityPlatform.String()] > 1 {
		errs = append(errs, fmt.Errorf("platform entity appears %d times", entityCount[OIDEntityPlatform.String()]))
	}
	if entityCount[OIDEntityTransaction.String()] > 1 {
		errs = append(errs, fmt.Errorf("transaction entity appears %d times", entityCount[OIDEntityTransaction.String()]))
	}

	keyIDs := map[string]struct{}{}
	for _, entity := range e.TBS.ReportedEntities {
		if !entity.EntityType.Equal(OIDEntityKey) {
			continue
		}
		ids := collectIdentifiers(entity)
		if len(ids) == 0 {
			errs = append(errs, fmt.Errorf("key entity missing identifier claim"))
			continue
		}
		for _, id := range ids {
			if _, ok := keyIDs[id]; ok {
				errs = append(errs, fmt.Errorf("duplicate key identifier %q across key entities", id))
			}
			keyIDs[id] = struct{}{}
		}
	}

	errs = append(errs, validateFIPSLevel(e)...)
	errs = append(errs, validateAKSPKIUniqueness(e)...)

	return errs
}

func validateClaim(entityTypeOID asn1.ObjectIdentifier, claim ReportedClaim) []error {
	spec, ok := ClaimSpecs[claim.ClaimType.String()]
	if !ok {
		return nil
	}

	var errs []error
	if !spec.EntityType.Equal(entityTypeOID) {
		errs = append(errs, fmt.Errorf("claim %s is not valid for entity %s", spec.Name, entityTypeOID.String()))
	}

	cv, err := DecodeClaimValue(claim.Value)
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
		if _, err := x509.ParsePKIXPublicKey(cv.Bytes); err != nil {
			errs = append(errs, fmt.Errorf("claim %s must contain a DER SubjectPublicKeyInfo: %v", spec.Name, err))
		}
	case claim.ClaimType.Equal(OIDClaimKeyPurpose):
		if _, err := DecodeCapabilities(cv.Bytes); err != nil {
			errs = append(errs, fmt.Errorf("claim %s must contain DER-encoded EvidenceKeyCapabilities: %v", spec.Name, err))
		}
	}

	return errs
}

func collectIdentifiers(entity ReportedEntity) []string {
	var ids []string
	for _, claim := range entity.ClaimSet {
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
	for _, entity := range e.TBS.ReportedEntities {
		if !entity.EntityType.Equal(OIDEntityPlatform) {
			continue
		}
		for _, claim := range entity.ClaimSet {
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
			if cv.Int < 1 || cv.Int > 4 {
				errs = append(errs, fmt.Errorf("fipslevel must be in range 1..4, got %d", cv.Int))
			}
		}
	}
	return errs
}

func validateAKSPKIUniqueness(e *Evidence) []error {
	var errs []error
	seen := map[string]struct{}{}
	for _, entity := range e.TBS.ReportedEntities {
		if !entity.EntityType.Equal(OIDEntityTransaction) {
			continue
		}
		for _, claim := range entity.ClaimSet {
			if !claim.ClaimType.Equal(OIDClaimTransactionAKSPKI) {
				continue
			}
			cv, err := DecodeClaimValue(claim.Value)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid ak-spki claim encoding: %v", err))
				continue
			}
			if cv.Kind != "bytes" {
				errs = append(errs, fmt.Errorf("ak-spki claim must be bytes, got %s", cv.Kind))
				continue
			}
			k := base64.StdEncoding.EncodeToString(cv.Bytes)
			if _, ok := seen[k]; ok {
				errs = append(errs, fmt.Errorf("ak-spki claim repeated with identical key material"))
			}
			seen[k] = struct{}{}
		}
	}
	return errs
}
