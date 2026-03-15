package evidence

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestValidateRejectsWrongClaimTypes(t *testing.T) {
	e := &Evidence{
		TBS: TbsPkixEvidence{
			Version: 1,
			ReportedEntities: []ReportedEntity{
				{
					EntityType: OIDEntityPlatform,
					ClaimSet: []ReportedClaim{
						{ClaimType: OIDClaimPlatformHWModel, Value: claimUTF8("not-bytes")},
					},
				},
				{
					EntityType: OIDEntityKey,
					ClaimSet: []ReportedClaim{
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
		"claim purpose must contain DER-encoded EvidenceKeyCapabilities",
	}
	for _, needle := range want {
		if !containsError(errs, needle) {
			t.Fatalf("Validate() errors did not contain %q: %v", needle, errs)
		}
	}
}

func TestValidateRejectsClaimInWrongEntity(t *testing.T) {
	e := &Evidence{
		TBS: TbsPkixEvidence{
			Version: 1,
			ReportedEntities: []ReportedEntity{
				{
					EntityType: OIDEntityPlatform,
					ClaimSet: []ReportedClaim{
						{ClaimType: OIDClaimTransactionNonce, Value: claimBytes([]byte("nonce"))},
					},
				},
			},
		},
	}

	errs := Validate(e)
	if !containsError(errs, "claim nonce is not valid for entity 1.2.3.999.0.1") {
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
		TBS: TbsPkixEvidence{
			Version: 1,
			ReportedEntities: []ReportedEntity{
				{
					EntityType: OIDEntityTransaction,
					ClaimSet: []ReportedClaim{
						{ClaimType: OIDClaimTransactionAKSPKI, Value: claimBytes(cert.RawSubjectPublicKeyInfo)},
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

	res := VerifyEvidence(e, VerifyOptions{})
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
		TBS: TbsPkixEvidence{
			Version: 1,
			ReportedEntities: []ReportedEntity{
				{
					EntityType: OIDEntityKey,
					ClaimSet: []ReportedClaim{
						{ClaimType: OIDClaimKeyIdentifier, Value: claimUTF8("key-1")},
						{ClaimType: OIDClaimKeySPKI, Value: claimBytes([]byte{0x01, 0x02, 0x03})},
					},
				},
				{
					EntityType: OIDEntityTransaction,
					ClaimSet: []ReportedClaim{
						{ClaimType: OIDClaimTransactionAKSPKI, Value: claimBytes([]byte{0x01, 0x02, 0x03})},
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
