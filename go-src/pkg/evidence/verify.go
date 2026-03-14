package evidence

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

type VerifyOptions struct {
	RequireAllSignatures  bool
	VerifyChains          bool
	Roots                 *x509.CertPool
	CurrentTime           time.Time
	RequireAttestationEKU bool
	AttestationEKUOIDs    []asn1.ObjectIdentifier
}

type SignatureResult struct {
	Index int
	OK    bool
	Error error
}

type VerifyResult struct {
	SignatureResults []SignatureResult
	ChainErrors      []error
	EKUErrors        []error
	AKSPKIMismatch   bool
}

func VerifyEvidence(e *Evidence, opts VerifyOptions) VerifyResult {
	res := VerifyResult{}

	for i, sig := range e.Signatures {
		pub, cert, err := signerPublicKey(sig.SID, e)
		if err != nil {
			res.SignatureResults = append(res.SignatureResults, SignatureResult{Index: i, OK: false, Error: err})
			continue
		}

		if cert != nil && opts.VerifyChains {
			if opts.Roots == nil {
				res.ChainErrors = append(res.ChainErrors, fmt.Errorf("signature %d: no roots configured for chain verification", i))
			} else {
				intermediates := x509.NewCertPool()
				for _, ic := range e.IntermediateCertificates {
					intermediates.AddCert(ic)
				}
				verifyOpts := x509.VerifyOptions{
					Roots:         opts.Roots,
					Intermediates: intermediates,
					CurrentTime:   opts.CurrentTime,
				}
				if _, err := cert.Verify(verifyOpts); err != nil {
					res.ChainErrors = append(res.ChainErrors, fmt.Errorf("signature %d: chain verification failed: %w", i, err))
				}
			}
		}

		if cert != nil && opts.RequireAttestationEKU {
			if err := verifyAttestationEKU(cert, opts.AttestationEKUOIDs); err != nil {
				res.EKUErrors = append(res.EKUErrors, fmt.Errorf("signature %d: %w", i, err))
			}
		}

		err = verifySignature(pub, sig.SignatureAlgorithm, e.TBSDER, sig.SignatureValue)
		if err != nil {
			res.SignatureResults = append(res.SignatureResults, SignatureResult{Index: i, OK: false, Error: err})
		} else {
			res.SignatureResults = append(res.SignatureResults, SignatureResult{Index: i, OK: true})
		}
	}

	if hasAKSPKI := hasAKSPKIClaim(e); hasAKSPKI {
		res.AKSPKIMismatch = !verifyAKSPKIMatch(e)
	}

	if opts.RequireAllSignatures {
		for _, r := range res.SignatureResults {
			if !r.OK {
				return res
			}
		}
	}

	return res
}

func signerPublicKey(sid SignerIdentifier, e *Evidence) (crypto.PublicKey, *x509.Certificate, error) {
	if hasRawValue(sid.Certificate) {
		certBytes := rawBytes(sid.Certificate)
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse signer certificate: %w", err)
		}
		return cert.PublicKey, cert, nil
	}
	if hasRawValue(sid.SubjectPublicKeyInfo) {
		pub, err := x509.ParsePKIXPublicKey(rawBytes(sid.SubjectPublicKeyInfo))
		if err != nil {
			return nil, nil, fmt.Errorf("parse signer spki: %w", err)
		}
		return pub, nil, nil
	}
	if len(sid.KeyID) > 0 {
		for _, cert := range e.IntermediateCertificates {
			if bytesEqual(cert.SubjectKeyId, sid.KeyID) {
				return cert.PublicKey, cert, nil
			}
		}
		return nil, nil, errors.New("signer keyId present but no matching certificate found")
	}
	return nil, nil, errors.New("no signer public key found")
}

func verifySignature(pub crypto.PublicKey, alg pkix.AlgorithmIdentifier, data, sig []byte) error {
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
	params := rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	hashFunc := crypto.SHA1
	if len(der) == 0 {
		return &params, hashFunc, nil
	}
	var parsed rsassaPSSParams
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, 0, fmt.Errorf("parse rsa-pss params: %w", err)
	}

	if !parsed.HashAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{}) {
		h, err := hashFromOID(parsed.HashAlgorithm.Algorithm)
		if err != nil {
			return nil, 0, err
		}
		hashFunc = h
	}
	if parsed.SaltLength != 0 {
		params.SaltLength = parsed.SaltLength
	}
	return &params, hashFunc, nil
}

type rsassaPSSParams struct {
	HashAlgorithm    pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength       int                      `asn1:"optional,explicit,tag:2"`
	TrailerField     int                      `asn1:"optional,explicit,tag:3"`
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

func hasAKSPKIClaim(e *Evidence) bool {
	for _, entity := range e.TBS.ReportedEntities {
		if !entity.EntityType.Equal(OIDEntityTransaction) {
			continue
		}
		for _, claim := range entity.ClaimSet {
			if claim.ClaimType.Equal(OIDClaimTransactionAKSPKI) {
				return true
			}
		}
	}
	return false
}

func verifyAKSPKIMatch(e *Evidence) bool {
	var akSpkis [][]byte
	for _, entity := range e.TBS.ReportedEntities {
		if !entity.EntityType.Equal(OIDEntityTransaction) {
			continue
		}
		for _, claim := range entity.ClaimSet {
			if !claim.ClaimType.Equal(OIDClaimTransactionAKSPKI) {
				continue
			}
			cv, err := DecodeClaimValue(claim.Value)
			if err != nil || cv.Kind != "bytes" {
				continue
			}
			akSpkis = append(akSpkis, cv.Bytes)
		}
	}
	if len(akSpkis) == 0 {
		return true
	}

	if len(e.Signatures) == 0 {
		return false
	}
	for _, sig := range e.Signatures {
		spki, err := signerSPKI(sig.SID, e)
		if err != nil {
			return false
		}
		matched := false
		for _, ak := range akSpkis {
			if bytesEqual(ak, spki) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func signerSPKI(sid SignerIdentifier, e *Evidence) ([]byte, error) {
	if hasRawValue(sid.SubjectPublicKeyInfo) {
		return rawBytes(sid.SubjectPublicKeyInfo), nil
	}
	if hasRawValue(sid.Certificate) {
		cert, err := x509.ParseCertificate(rawBytes(sid.Certificate))
		if err != nil {
			return nil, err
		}
		return cert.RawSubjectPublicKeyInfo, nil
	}
	if len(sid.KeyID) > 0 {
		for _, cert := range e.IntermediateCertificates {
			if bytesEqual(cert.SubjectKeyId, sid.KeyID) {
				return cert.RawSubjectPublicKeyInfo, nil
			}
		}
	}
	return nil, errors.New("no spki available")
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
