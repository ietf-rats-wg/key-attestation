package evidence

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// KeyResolver returns the public key and optionally its certificate for an opaque keyId.
// Resolution is separate from trust: roots or a pinned SPKI are still required.
type KeyResolver func([]byte) (crypto.PublicKey, *x509.Certificate, error)

type VerifyOptions struct {
	AllowedSignatureAlgorithms []asn1.ObjectIdentifier // nil accepts all implemented algorithms.
	RequireAllSignatures       bool
	VerifyChains               bool
	Roots                      *x509.CertPool
	CurrentTime                time.Time
	RequireAttestationEKU      bool                    // Deprecated: KU/EKU checks are always mandatory.
	AttestationEKUOIDs         []asn1.ObjectIdentifier // Additional accepted draft EKU assignments.
	ResolveKeyID               KeyResolver
	TrustedSPKIs               [][]byte
	SignatureOnly              bool   // Explicit diagnostic mode: no trust decision.
	ExpectedNonce              []byte // nil disables freshness checking.
}

type SignatureResult struct {
	Index int
	OK    bool // Includes certificate requirements, binding, and configured trust policy.
	Error error
}

type VerifyResult struct {
	SignatureResults []SignatureResult
	Errors           []error // Envelope-wide failures, including identity and unresolved keyId.
	ChainErrors      []error // Diagnostic only; block acceptance uses SignatureResults.
	EKUErrors        []error
	AKSPKIMismatch   bool
	VerifiedAKSPKIs  [][]byte // Only backed by acceptable, verified signature blocks.
	Accepted         bool
}

func VerifyEvidence(e *Evidence, opts VerifyOptions) VerifyResult {
	res := VerifyResult{}
	res.Errors = append(res.Errors, Validate(e)...)
	canonical, err := asn1.Marshal(e.TBS)
	if err != nil || !bytes.Equal(canonical, e.TBSDER) {
		res.Errors = append(res.Errors, errors.New("TBS model does not match signed DER"))
	}
	if len(res.Errors) > 0 {
		return res
	}
	if opts.ExpectedNonce != nil {
		found := false
		for _, el := range e.TBS.ReportedElements {
			for _, c := range el.Claims {
				if el.ElementType.Equal(OIDElementTransaction) && c.ClaimType.Equal(OIDClaimTransactionNonce) {
					cv, _ := DecodeClaimValue(c.Value)
					found = bytes.Equal(cv.Bytes, opts.ExpectedNonce)
				}
			}
		}
		if !found {
			res.Errors = append(res.Errors, errors.New("missing or mismatched verifier nonce"))
		}
	}
	var subject []byte
	seenCertKeys := map[string]bool{}
	recordIdentity := func(cert *x509.Certificate) {
		if subject == nil {
			subject = cert.RawSubject
		} else if !bytes.Equal(subject, cert.RawSubject) {
			res.Errors = append(res.Errors, errors.New("signing certificates represent different Attester identities"))
		}
		spki := cert.RawSubjectPublicKeyInfo
		if cert.PublicKey != nil {
			if canonical, err := x509.MarshalPKIXPublicKey(cert.PublicKey); err == nil {
				spki = canonical
			}
		}
		if seenCertKeys[string(spki)] {
			res.Errors = append(res.Errors, errors.New("signing certificates must contain distinct SPKIs"))
		}
		seenCertKeys[string(spki)] = true
	}
	akClaims := attestationSPKIs(e)
	for i, sig := range e.Signatures {
		result := SignatureResult{Index: i}
		embeddedIdentity := false
		if hasRawValue(sig.SID.Certificate) {
			if embedded, err := x509.ParseCertificate(rawBytes(sig.SID.Certificate)); err == nil {
				recordIdentity(embedded)
				embeddedIdentity = true
			}
		}
		pub, cert, err := resolveSigner(sig.SID, e, opts.ResolveKeyID)
		if err != nil {
			result.Error = err
			if errors.Is(err, errUnresolvedKeyID) || errors.Is(err, errInconsistentSID) {
				res.Errors = append(res.Errors, err)
			}
			res.SignatureResults = append(res.SignatureResults, result)
			continue
		}
		spki, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			result.Error = err
			res.SignatureResults = append(res.SignatureResults, result)
			continue
		}
		if cert != nil {
			if !embeddedIdentity {
				recordIdentity(cert)
			}
			err = checkAttestationCertificate(cert, opts.AttestationEKUOIDs)
			now := opts.CurrentTime
			if now.IsZero() {
				now = time.Now()
			}
			if err == nil && (now.Before(cert.NotBefore) || now.After(cert.NotAfter)) {
				err = errors.New("signer certificate is not valid at verification time")
			}
			if err != nil {
				res.EKUErrors = append(res.EKUErrors, fmt.Errorf("signature %d: %w", i, err))
			}
		}
		if err == nil && opts.AllowedSignatureAlgorithms != nil {
			allowed := false
			for _, oid := range opts.AllowedSignatureAlgorithms {
				if sig.SignatureAlgorithm.Algorithm.Equal(oid) {
					allowed = true
				}
			}
			if !allowed {
				err = errors.New("signature algorithm excluded by appraisal policy")
			}
		}
		if err == nil {
			err = verifySignature(pub, sig.SignatureAlgorithm, e.TBSDER, sig.SignatureValue)
		}
		matched := containsSPKI(akClaims, spki)
		if len(akClaims) > 0 && !matched {
			res.AKSPKIMismatch = true
			res.Errors = append(res.Errors, fmt.Errorf("signature %d: signer not present in ak-spki claims", i))
		}
		if err == nil && (opts.VerifyChains || opts.Roots != nil) {
			if cert == nil || opts.Roots == nil {
				err = errors.New("certificate and trust roots required for path validation")
			} else {
				intermediates := x509.NewCertPool()
				for _, ic := range e.IntermediateCertificates {
					intermediates.AddCert(ic)
				}
				// The custom EKU was checked above. ExtKeyUsageAny avoids Go's TLS default.
				// Go does not recognize a critical custom EKU; handle only that extension here.
				copyCert := *cert
				copyCert.UnhandledCriticalExtensions = nil
				for _, oid := range cert.UnhandledCriticalExtensions {
					if !oid.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
						copyCert.UnhandledCriticalExtensions = append(copyCert.UnhandledCriticalExtensions, oid)
					}
				}
				_, err = copyCert.Verify(x509.VerifyOptions{Roots: opts.Roots, Intermediates: intermediates, CurrentTime: opts.CurrentTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			}
			if err != nil {
				res.ChainErrors = append(res.ChainErrors, fmt.Errorf("signature %d: %w", i, err))
			}
		} else if err == nil && !opts.SignatureOnly && !containsSPKI(opts.TrustedSPKIs, spki) {
			err = errors.New("no trusted path or pinned signer SPKI; use signature-only mode for diagnostics")
		}
		result.Error = err
		result.OK = err == nil
		res.SignatureResults = append(res.SignatureResults, result)
		if result.OK {
			res.Accepted = true
			if matched {
				res.VerifiedAKSPKIs = append(res.VerifiedAKSPKIs, spki)
			}
		}
	}
	if opts.RequireAllSignatures {
		for _, r := range res.SignatureResults {
			if !r.OK {
				res.Accepted = false
			}
		}
	}
	if len(res.Errors) > 0 {
		res.Accepted = false
	}
	return res
}

var errUnresolvedKeyID = errors.New("unresolved signer keyId")
var errInconsistentSID = errors.New("inconsistent SignerIdentifier")

func resolveSigner(sid SignerIdentifier, e *Evidence, resolver KeyResolver) (crypto.PublicKey, *x509.Certificate, error) {
	var pub crypto.PublicKey
	var cert *x509.Certificate
	var keys []crypto.PublicKey
	if hasRawValue(sid.Certificate) {
		var err error
		cert, err = x509.ParseCertificate(rawBytes(sid.Certificate))
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, cert.PublicKey)
	}
	if hasRawValue(sid.SubjectPublicKeyInfo) {
		key, err := x509.ParsePKIXPublicKey(rawBytes(sid.SubjectPublicKeyInfo))
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, key)
	}
	if sid.KeyID != nil {
		var key crypto.PublicKey
		var resolvedCert *x509.Certificate
		var err error
		if resolver != nil {
			key, resolvedCert, err = resolver(sid.KeyID)
		} else {
			candidates := append([]*x509.Certificate{}, e.IntermediateCertificates...)
			if cert != nil {
				candidates = append(candidates, cert)
			}
			for _, candidate := range candidates {
				if len(candidate.SubjectKeyId) > 0 && bytes.Equal(candidate.SubjectKeyId, sid.KeyID) {
					if key != nil {
						a, _ := x509.MarshalPKIXPublicKey(key)
						b, _ := x509.MarshalPKIXPublicKey(candidate.PublicKey)
						if !bytes.Equal(a, b) {
							return nil, nil, fmt.Errorf("%w: ambiguous keyId", errInconsistentSID)
						}
					}
					key = candidate.PublicKey
					resolvedCert = candidate
				}
			}
		}
		if err != nil || key == nil {
			return nil, nil, fmt.Errorf("%w: %v", errUnresolvedKeyID, err)
		}
		keys = append(keys, key)
		if resolvedCert != nil {
			keys = append(keys, resolvedCert.PublicKey)
			if cert == nil {
				cert = resolvedCert
			}
		}
	}
	for _, key := range keys {
		if pub != nil {
			a, _ := x509.MarshalPKIXPublicKey(pub)
			b, _ := x509.MarshalPKIXPublicKey(key)
			if !bytes.Equal(a, b) {
				return nil, nil, errInconsistentSID
			}
		}
		pub = key
	}
	if pub == nil {
		return nil, nil, errors.New("no signer public key")
	}
	return pub, cert, nil
}

func checkAttestationCertificate(cert *x509.Certificate, additional []asn1.ObjectIdentifier) error {
	if cert.IsCA {
		return errors.New("signer must be an end-entity certificate")
	}
	hasKU := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
			hasKU = true
		}
	}
	if !hasKU || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate missing digitalSignature KeyUsage")
	}
	expected := append([]asn1.ObjectIdentifier{OIDAttestationKey}, additional...)
	return verifyAttestationEKU(cert, expected)
}

func attestationSPKIs(e *Evidence) [][]byte {
	var result [][]byte
	for _, el := range e.TBS.ReportedElements {
		if el.ElementType.Equal(OIDElementTransaction) {
			for _, c := range el.Claims {
				if c.ClaimType.Equal(OIDClaimTransactionAKSPKI) {
					cv, err := DecodeClaimValueFor(c.ClaimType, c.Value)
					if err == nil && cv.Kind == "spki" {
						keyBytes := cv.Bytes
						if key, err := x509.ParsePKIXPublicKey(keyBytes); err == nil {
							if canonical, err := x509.MarshalPKIXPublicKey(key); err == nil {
								keyBytes = canonical
							}
						}
						result = append(result, keyBytes)
					}
				}
			}
		}
	}
	return result
}
func containsSPKI(values [][]byte, value []byte) bool {
	for _, v := range values {
		if bytes.Equal(v, value) {
			return true
		}
	}
	return false
}

func verifySignature(pub crypto.PublicKey, alg pkix.AlgorithmIdentifier, data, sig []byte) error {
	if alg.Algorithm.Equal(oidEd25519) || alg.Algorithm.Equal(oidECDSAWithSHA256) || alg.Algorithm.Equal(oidECDSAWithSHA384) || alg.Algorithm.Equal(oidECDSAWithSHA512) {
		if hasRawValue(alg.Parameters) {
			return errors.New("signature algorithm parameters must be absent")
		}
	}
	if alg.Algorithm.Equal(oidSHA1WithRSA) || alg.Algorithm.Equal(oidSHA256WithRSA) || alg.Algorithm.Equal(oidSHA384WithRSA) || alg.Algorithm.Equal(oidSHA512WithRSA) {
		if hasRawValue(alg.Parameters) {
			der, err := asn1.Marshal(alg.Parameters)
			if err != nil || !bytes.Equal(der, []byte{5, 0}) {
				return errors.New("RSA signature parameters must be NULL or absent")
			}
		}
	}
	switch {
	case alg.Algorithm.Equal(oidRSASSAPSS):
		pssOpts, hashFunc, err := parsePSSParams(alg.Parameters.FullBytes)
		if err != nil {
			return err
		}
		h := hashFunc.New()
		h.Write(data)
		digest := h.Sum(nil)
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("rsa-pss requires rsa public key")
		}
		if pssOpts.SaltLength == 0 {
			return errors.New("zero-length RSA-PSS salt is not supported")
		}
		return rsa.VerifyPSS(rsaPub, hashFunc, digest, sig, pssOpts)

	case alg.Algorithm.Equal(oidSHA256WithRSA), alg.Algorithm.Equal(oidSHA384WithRSA), alg.Algorithm.Equal(oidSHA512WithRSA), alg.Algorithm.Equal(oidSHA1WithRSA):
		hashFunc, err := hashForRSA(alg.Algorithm)
		if err != nil {
			return err
		}
		h := hashFunc.New()
		h.Write(data)
		digest := h.Sum(nil)
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("rsa signature requires rsa public key")
		}
		return rsa.VerifyPKCS1v15(rsaPub, hashFunc, digest, sig)

	case alg.Algorithm.Equal(oidECDSAWithSHA256), alg.Algorithm.Equal(oidECDSAWithSHA384), alg.Algorithm.Equal(oidECDSAWithSHA512):
		hashFunc, err := hashForECDSA(alg.Algorithm)
		if err != nil {
			return err
		}
		h := hashFunc.New()
		h.Write(data)
		digest := h.Sum(nil)
		pubKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ecdsa signature requires ecdsa public key")
		}
		if !ecdsa.VerifyASN1(pubKey, digest, sig) {
			return errors.New("ecdsa signature verification failed")
		}
		return nil

	case alg.Algorithm.Equal(oidEd25519):
		pubKey, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("ed25519 signature requires ed25519 public key")
		}
		if !ed25519.Verify(pubKey, data, sig) {
			return errors.New("ed25519 signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported signature algorithm OID %s", alg.Algorithm.String())
	}
}

func parsePSSParams(der []byte) (*rsa.PSSOptions, crypto.Hash, error) {
	if len(der) == 0 {
		return nil, 0, errors.New("RSA-PSS parameters are required")
	}
	defaultSHA1 := []byte{0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00}
	fields, err := sequenceFields(der, 0, 4)
	if err != nil {
		return nil, 0, err
	}
	hashFunc := crypto.SHA1
	mgfHash := crypto.SHA1
	salt := 20
	trailer := 1
	previous := -1
	for _, field := range fields {
		if field.Class != 2 || !field.IsCompound || field.Tag <= previous || field.Tag > 3 {
			return nil, 0, errors.New("invalid RSA-PSS parameter tag")
		}
		previous = field.Tag
		switch field.Tag {
		case 0:
			hashFunc, err = decodePSSHash(field.Bytes)
			if err == nil && bytes.Equal(field.Bytes, defaultSHA1) {
				err = errors.New("DER must omit default PSS hash")
			}
		case 1:
			var alg pkix.AlgorithmIdentifier
			if _, err = sequenceFields(field.Bytes, 2, 2); err == nil {
				err = unmarshalExact(field.Bytes, &alg)
			}
			if err == nil {
				if !alg.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}) {
					err = errors.New("RSA-PSS requires MGF1")
				} else {
					mgfHash, err = decodePSSHash(alg.Parameters.FullBytes)
				}
			}
			if err == nil && bytes.Equal(alg.Parameters.FullBytes, defaultSHA1) {
				err = errors.New("DER must omit default PSS mask generator")
			}

		case 2:
			err = unmarshalExact(field.Bytes, &salt)
			if err == nil && salt == 20 {
				err = errors.New("DER must omit default PSS salt length")
			}
		case 3:
			err = unmarshalExact(field.Bytes, &trailer)
			if err == nil && trailer == 1 {
				err = errors.New("DER must omit default PSS trailer")
			}
		}
		if err != nil {
			return nil, 0, err
		}
	}
	// crypto/rsa uses the message hash for MGF1; reject unsupported combinations.
	if mgfHash != hashFunc || salt < 0 || trailer != 1 {
		return nil, 0, errors.New("unsupported RSA-PSS MGF hash, salt length or trailer")
	}
	return &rsa.PSSOptions{SaltLength: salt, Hash: hashFunc}, hashFunc, nil
}

func decodePSSHash(der []byte) (crypto.Hash, error) {
	if _, err := sequenceFields(der, 1, 2); err != nil {
		return 0, err
	}
	var alg pkix.AlgorithmIdentifier
	if err := unmarshalExact(der, &alg); err != nil {
		return 0, err
	}
	if hasRawValue(alg.Parameters) {
		parameters, err := asn1.Marshal(alg.Parameters)
		if err != nil || !bytes.Equal(parameters, []byte{5, 0}) {
			return 0, errors.New("hash parameters must be NULL or absent")
		}
	}
	return hashFromOID(alg.Algorithm)
}

func hashForRSA(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA256WithRSA):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384WithRSA):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512WithRSA):
		return crypto.SHA512, nil
	case oid.Equal(oidSHA1WithRSA):
		return crypto.SHA1, nil
	default:
		return 0, fmt.Errorf("unsupported rsa hash algorithm %s", oid.String())
	}
}

func hashForECDSA(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidECDSAWithSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidECDSAWithSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidECDSAWithSHA512):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported ecdsa hash algorithm %s", oid.String())
	}
}

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1, nil
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm %s", oid.String())
	}
}

func verifyAttestationEKU(cert *x509.Certificate, expected []asn1.ObjectIdentifier) error {
	if len(expected) == 0 {
		return errors.New("attestation EKU check requested but no attestation EKU OID configured")
	}
	for _, oid := range expected {
		for _, got := range cert.UnknownExtKeyUsage {
			if got.Equal(oid) {
				return nil
			}
		}
	}
	return fmt.Errorf("certificate missing required attestation EKU (%v)", expected)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidSHA1WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSASSAPSS     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)
