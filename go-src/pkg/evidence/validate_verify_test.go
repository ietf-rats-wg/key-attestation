package evidence

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestValidateRejectsWrongClaimTypes(t *testing.T) {
	e := &Evidence{
		TBS: TbsEvidence{
			Version: 1,
			ReportedElements: []ReportedElement{
				{
					ElementType: OIDElementPlatform,
					Claims: []ReportedClaim{
						{ClaimType: OIDClaimPlatformHWModel, Value: claimUTF8("not-bytes")},
					},
				},
				{
					ElementType: OIDElementKey,
					Claims: []ReportedClaim{
						{ClaimType: OIDClaimKeyIdentifier, Value: claimBytes([]byte("not-a-string"))},
						{ClaimType: OIDClaimKeyPurpose, Value: claimBytes([]byte{0x06, 0x03, 0x2a, 0x03, 0xe7})},
					},
				},
			},
		},
	}

	errs := Validate(e)
	if len(errs) == 0 {
		t.Fatal("Validate() returned no errors for malformed claim types")
	}

	want := []string{
		"claim hwmodel must be bytes",
		"claim identifier must be utf8String",
		"claim purpose must be purposes",
	}
	for _, needle := range want {
		if !containsError(errs, needle) {
			t.Fatalf("Validate() errors did not contain %q: %v", needle, errs)
		}
	}
}

func TestValidateRejectsClaimInWrongEntity(t *testing.T) {
	e := &Evidence{
		TBS: TbsEvidence{
			Version: 1,
			ReportedElements: []ReportedElement{
				{
					ElementType: OIDElementPlatform,
					Claims: []ReportedClaim{
						{ClaimType: OIDClaimTransactionNonce, Value: claimBytes([]byte("nonce"))},
					},
				},
			},
		},
	}

	errs := Validate(e)
	if !containsError(errs, "claim nonce is not valid for element 1.3.6.1.5.5.999.0.1") {
		t.Fatalf("Validate() did not reject misplaced claim: %v", errs)
	}
}

func TestVerifyEvidenceMatchesAKSPKIForKeyIDSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}

	cert, err := testCertificate(key, []byte{0x01, 0x02, 0x03, 0x04})
	if err != nil {
		t.Fatalf("testCertificate(): %v", err)
	}

	tbsDER := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	sigAlg, signature, err := signTBS(tbsDER, key)
	if err != nil {
		t.Fatalf("signTBS(): %v", err)
	}

	e := &Evidence{
		TBS: TbsEvidence{
			Version: 1,
			ReportedElements: []ReportedElement{
				{
					ElementType: OIDElementTransaction,
					Claims: []ReportedClaim{
						{ClaimType: OIDClaimTransactionAKSPKI, Value: claimSPKI(cert.RawSubjectPublicKeyInfo)},
					},
				},
			},
		},
		TBSDER: tbsDER,
		Signatures: []SignatureBlock{
			{
				SID: SignerIdentifier{
					KeyID: cert.SubjectKeyId,
				},
				SignatureAlgorithm: sigAlg,
				SignatureValue:     signature,
			},
		},
		IntermediateCertificates: []*x509.Certificate{cert},
	}

	e.TBSDER, err = asn1.Marshal(e.TBS)
	if err != nil {
		t.Fatal(err)
	}
	e.Signatures[0].SignatureAlgorithm, e.Signatures[0].SignatureValue, err = signTBS(e.TBSDER, key)
	if err != nil {
		t.Fatal(err)
	}
	res := VerifyEvidence(e, VerifyOptions{SignatureOnly: true})
	if len(res.SignatureResults) != 1 || !res.SignatureResults[0].OK {
		t.Fatalf("VerifyEvidence() signature failed: %+v", res)
	}
	if res.AKSPKIMismatch {
		t.Fatalf("VerifyEvidence() reported ak-spki mismatch for keyId-based signer: %+v", res)
	}
}

func TestReadEvidenceAcceptsEvidencePEM(t *testing.T) {
	der, err := GenerateSample()
	if err != nil {
		t.Fatalf("GenerateSample(): %v", err)
	}
	pemData, err := FormatEvidence(der, "pem")
	if err != nil {
		t.Fatalf("FormatEvidence(): %v", err)
	}
	got, err := ReadEvidence(pemData, "auto")
	if err != nil {
		t.Fatalf("ReadEvidence(): %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Fatal("ReadEvidence() returned different DER bytes for EVIDENCE PEM input")
	}
}

func TestReadEvidenceRejectsUnexpectedPEMType(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01, 0x02, 0x03}})
	_, err := ReadEvidence(pemData, "pem")
	if err == nil {
		t.Fatal("ReadEvidence() accepted a non-EVIDENCE PEM block")
	}
	if !strings.Contains(err.Error(), "unexpected PEM block type") {
		t.Fatalf("ReadEvidence() returned wrong error: %v", err)
	}
}

func containsError(errs []error, needle string) bool {
	for _, err := range errs {
		if strings.Contains(err.Error(), needle) {
			return true
		}
	}
	return false
}

func testCertificate(key crypto.Signer, subjectKeyID []byte) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "pkix-evidence test signer",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{OIDAttestationKey},
		BasicConstraintsValid: true,
		SubjectKeyId:          append([]byte(nil), subjectKeyID...),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func TestValidateRejectsInvalidSPKIBytes(t *testing.T) {
	e := &Evidence{
		TBS: TbsEvidence{
			Version: 1,
			ReportedElements: []ReportedElement{
				{
					ElementType: OIDElementKey,
					Claims: []ReportedClaim{
						{ClaimType: OIDClaimKeyIdentifier, Value: claimUTF8("key-1")},
						{ClaimType: OIDClaimKeySPKI, Value: claimSPKI([]byte{0x30, 0x01, 0x02})},
					},
				},
				{
					ElementType: OIDElementTransaction,
					Claims: []ReportedClaim{
						{ClaimType: OIDClaimTransactionAKSPKI, Value: claimSPKI([]byte{0x30, 0x01, 0x02})},
					},
				},
			},
		},
	}

	errs := Validate(e)
	if !containsError(errs, "claim spki must contain a DER SubjectPublicKeyInfo") {
		t.Fatalf("Validate() did not reject invalid key spki claim: %v", errs)
	}
	if !containsError(errs, "claim ak-spki must contain a DER SubjectPublicKeyInfo") {
		t.Fatalf("Validate() did not reject invalid ak-spki claim: %v", errs)
	}
}

func TestValidateRejectsOctetStringSPKIClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	e := &Evidence{
		TBS: TbsEvidence{
			Version: 1,
			ReportedElements: []ReportedElement{
				{
					ElementType: OIDElementTransaction,
					Claims: []ReportedClaim{
						{ClaimType: OIDClaimTransactionAKSPKI, Value: claimBytes(spki)},
					},
				},
			},
		},
	}

	e.TBS.ReportedElements = append(e.TBS.ReportedElements, ReportedElement{
		ElementType: OIDElementKey,
		Claims: []ReportedClaim{
			{ClaimType: OIDClaimKeyIdentifier, Value: claimUTF8("key-1")},
			{ClaimType: OIDClaimKeySPKI, Value: claimBytes(spki)},
		},
	})

	errs := Validate(e)
	if !containsError(errs, "claim spki must be spki, got bytes") {
		t.Fatalf("Validate() accepted an OCTET STRING key spki claim: %v", errs)
	}
	if !containsError(errs, "claim ak-spki must be spki, got bytes") {
		t.Fatalf("Validate() accepted an OCTET STRING ak-spki claim: %v", errs)
	}
}
