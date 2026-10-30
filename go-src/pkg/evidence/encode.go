package evidence

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// GenerateSample creates a signed example. Unsigned Evidence is not valid.
func GenerateSample() ([]byte, error) {
	return GenerateSampleSigned(SignOptions{})
}

type SignOptions struct {
	WithAKSPKI bool // Deprecated: AK binding is always included.
	Nonce      []byte
	KeyPath    string
	CertPath   string
}

func GenerateSampleSigned(opts SignOptions) ([]byte, error) {
	var (
		key     crypto.PrivateKey
		certDER []byte
		err     error
	)

	if opts.KeyPath != "" {
		key, err = loadPrivateKeyPEM(opts.KeyPath)
		if err != nil {
			return nil, err
		}
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	if opts.CertPath != "" {
		certDER, err = loadCertificatePEM(opts.CertPath)
		if err != nil {
			return nil, err
		}
	} else {
		certDER, err = selfSignedCertDER(key)
		if err != nil {
			return nil, err
		}
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	pub, err := publicKeyFromPrivate(key)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil || !bytes.Equal(spki, cert.RawSubjectPublicKeyInfo) {
		return nil, errors.New("signing key does not match certificate")
	}
	if err := checkAttestationCertificate(cert, nil); err != nil {
		return nil, err
	}
	tbsDER, err := buildSampleTBS(true, cert.RawSubjectPublicKeyInfo, opts.Nonce)
	if err != nil {
		return nil, err
	}

	sigAlg, signature, err := signTBS(tbsDER, key)
	if err != nil {
		return nil, err
	}

	sig := signatureBlockMarshal{
		SID: signerIdentifierMarshal{
			Certificate: explicitTag(2, certDER),
		},
		SignatureAlgorithm: sigAlg,
		SignatureValue:     signature,
	}

	evidence := pkixEvidenceMarshal{
		TBS:        asn1.RawValue{FullBytes: tbsDER},
		Signatures: []signatureBlockMarshal{sig},
	}
	return asn1.Marshal(evidence)
}

func FormatEvidence(der []byte, format string) ([]byte, error) {
	switch format {
	case "der":
		return der, nil
	case "base64":
		out := make([]byte, base64.StdEncoding.EncodedLen(len(der)))
		base64.StdEncoding.Encode(out, der)
		return append(out, '\n'), nil
	case "pem":
		block := &pem.Block{Type: "EVIDENCE", Bytes: der}
		buf := &bytes.Buffer{}
		if err := pem.Encode(buf, block); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unknown format: %s", format)
	}
}

func claimPurposes(oids []asn1.ObjectIdentifier) asn1.RawValue {
	der, _ := asn1.Marshal(oids)
	return asn1.RawValue{FullBytes: der}
}

func claimBytes(b []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, IsCompound: false, Bytes: b}
}

// claimSPKI carries a DER SubjectPublicKeyInfo as the claim value itself.
func claimSPKI(der []byte) asn1.RawValue {
	return asn1.RawValue{FullBytes: der}
}

func claimUTF8(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, IsCompound: false, Bytes: []byte(s)}
}

func claimBool(v bool) asn1.RawValue {
	byteVal := byte(0)
	if v {
		byteVal = 0xff
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagBoolean, IsCompound: false, Bytes: []byte{byteVal}}
}

func claimTime(t time.Time) asn1.RawValue {
	ts := t.UTC().Format("20060102150405Z")
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagGeneralizedTime, IsCompound: false, Bytes: []byte(ts)}
}

func claimInt(v int64) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagInteger, IsCompound: false, Bytes: asn1Content(v)}
}

func asn1Content(v interface{}) []byte {
	der, err := asn1.Marshal(v)
	if err != nil {
		return nil
	}
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		return nil
	}
	return rv.Bytes
}

type tbsEvidenceMarshal struct {
	Version          int
	ReportedElements []reportedElementMarshal
}

type reportedElementMarshal struct {
	ElementType asn1.ObjectIdentifier
	Claims      []reportedClaimMarshal
}

type reportedClaimMarshal struct {
	ClaimType asn1.ObjectIdentifier
	Value     asn1.RawValue
}

type pkixEvidenceMarshal struct {
	TBS                      asn1.RawValue
	Signatures               []signatureBlockMarshal
	IntermediateCertificates []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type signatureBlockMarshal struct {
	SID                signerIdentifierMarshal
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     []byte
}

type signerIdentifierMarshal struct {
	KeyID                asn1.RawValue `asn1:"optional"`
	SubjectPublicKeyInfo asn1.RawValue `asn1:"optional"`
	Certificate          asn1.RawValue `asn1:"optional"`
}

func buildSampleTBS(withAKSPKI bool, akSPKI []byte, nonces ...[]byte) ([]byte, error) {
	now := time.Now().UTC()
	nonce := []byte("nonce-1234") // Demonstration only; callers should supply a verifier nonce.
	if len(nonces) > 0 && nonces[0] != nil {
		nonce = nonces[0]
	}

	transactionClaims := []reportedClaimMarshal{
		{ClaimType: OIDClaimTransactionNonce, Value: claimBytes(nonce)},
		{ClaimType: OIDClaimTransactionTimestamp, Value: claimTime(now)},
	}
	if withAKSPKI && len(akSPKI) > 0 {
		transactionClaims = append(transactionClaims, reportedClaimMarshal{
			ClaimType: OIDClaimTransactionAKSPKI,
			Value:     claimSPKI(akSPKI),
		})
	}

	transaction := reportedElementMarshal{
		ElementType: OIDElementTransaction,
		Claims:      transactionClaims,
	}

	platform := reportedElementMarshal{
		ElementType: OIDElementPlatform,
		Claims: []reportedClaimMarshal{
			{ClaimType: OIDClaimPlatformVendor, Value: claimUTF8("IETF RATS")},
			{ClaimType: OIDClaimPlatformHWSerial, Value: claimUTF8("HSM-0001")},
			{ClaimType: OIDClaimPlatformFIPSBoot, Value: claimBool(true)},
			{ClaimType: OIDClaimPlatformFIPSVer, Value: claimUTF8("FIPS 140-3")},
			{ClaimType: OIDClaimPlatformFIPSLevel, Value: claimInt(3)},
		},
	}

	key := reportedElementMarshal{
		ElementType: OIDElementKey,
		Claims: []reportedClaimMarshal{
			{ClaimType: OIDClaimKeyIdentifier, Value: claimUTF8("key-001")},
			{ClaimType: OIDClaimKeyExtractable, Value: claimBool(false)},
			{ClaimType: OIDClaimKeySensitive, Value: claimBool(true)},
			{ClaimType: OIDClaimKeyLocal, Value: claimBool(true)},
			{ClaimType: OIDClaimKeyPurpose, Value: claimPurposes([]asn1.ObjectIdentifier{OIDKeyCapabilitySign, OIDKeyCapabilityDecapsulate})},
		},
	}

	tbs := tbsEvidenceMarshal{
		Version:          1,
		ReportedElements: []reportedElementMarshal{transaction, platform, key},
	}
	return asn1.Marshal(tbs)
}

func selfSignedCertDER(key crypto.PrivateKey) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	pub, err := publicKeyFromPrivate(key)
	if err != nil {
		return nil, err
	}
	ekuDER, err := asn1.Marshal([]asn1.ObjectIdentifier{OIDAttestationKey})
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "pkix-evidence test signer",
		},
		NotBefore:             time.Now().UTC().Add(-time.Hour),
		NotAfter:              time.Now().UTC().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtraExtensions:       []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuDER}},
		BasicConstraintsValid: true,
	}
	return x509.CreateCertificate(rand.Reader, &template, &template, pub, key)
}

func explicitTag(tag int, der []byte) asn1.RawValue {
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      der,
	}
}

func publicKeyFromPrivate(key crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey), nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
}

func loadPrivateKeyPEM(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in key file")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

func loadCertificatePEM(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in certificate file")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}
	return block.Bytes, nil
}

func signTBS(tbsDER []byte, key crypto.PrivateKey) (pkix.AlgorithmIdentifier, []byte, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(tbsDER)
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil {
			return pkix.AlgorithmIdentifier{}, nil, err
		}
		return pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}, sig, nil
	case *rsa.PrivateKey:
		digest := sha256.Sum256(tbsDER)
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		if err != nil {
			return pkix.AlgorithmIdentifier{}, nil, err
		}
		return pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.RawValue{Tag: asn1.TagNull}}, sig, nil
	case ed25519.PrivateKey:
		sig := ed25519.Sign(k, tbsDER)
		return pkix.AlgorithmIdentifier{Algorithm: oidEd25519}, sig, nil
	default:
		return pkix.AlgorithmIdentifier{}, nil, fmt.Errorf("unsupported private key type %T", key)
	}
}
