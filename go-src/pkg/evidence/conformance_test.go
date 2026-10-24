package evidence

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"testing"
	"time"
)

func signedExample(t *testing.T) *Evidence {
	t.Helper()
	der, err := GenerateSample()
	if err != nil {
		t.Fatal(err)
	}
	e, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestCurrentClaimReference(t *testing.T) {
	literal, _ := hex.DecodeString("3017060a2b0601050587670101000c0941636d6520436f7270")
	var claim ReportedClaim
	if err := unmarshalExact(literal, &claim); err != nil {
		t.Fatal(err)
	}
	if !claim.ClaimType.Equal(OIDClaimPlatformVendor) {
		t.Fatal(claim.ClaimType)
	}
	cv, err := DecodeClaimValue(claim.Value)
	if err != nil || cv.Kind != "utf8String" || cv.String != "Acme Corp" {
		t.Fatalf("%+v %v", cv, err)
	}
	der, err := asn1.Marshal(ReportedClaim{OIDClaimPlatformVendor, claimUTF8("Acme Corp")})
	if err != nil || !bytes.Equal(literal, der) {
		t.Fatalf("%x %v", der, err)
	}
}

func TestCurrentSampleAndExplicitCertificates(t *testing.T) {
	e := signedExample(t)
	if errs := Validate(e); len(errs) > 0 {
		t.Fatal(errs)
	}
	if result := VerifyEvidence(e, VerifyOptions{SignatureOnly: true}); !result.Accepted || len(result.VerifiedAKSPKIs) != 1 {
		t.Fatalf("%+v", result)
	}
	cert, err := x509.ParseCertificate(rawBytes(e.Signatures[0].SID.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	raw := e.Raw
	raw.IntermediateCertificates = []asn1.RawValue{{FullBytes: cert.Raw}}
	der, err := asn1.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := sequenceFields(der, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := sequenceFields(fields[2].Bytes, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inner[0].FullBytes, cert.Raw) {
		t.Fatal("missing EXPLICIT SEQUENCE wrapper")
	}
	if _, err := Parse(der); err != nil {
		t.Fatal(err)
	}
}

func TestRejectEmptyAndExtraEnvelopeFields(t *testing.T) {
	empty, _ := hex.DecodeString("3009300502010130003000")
	if _, err := Parse(empty); err == nil {
		t.Fatal("accepted empty Evidence")
	}
	e := signedExample(t)
	// Add a third TBS component: encoding/asn1's ordinary struct decoder ignores it.
	type extraTBS struct {
		Version  int
		Elements []ReportedElement
		Extra    bool
	}
	tbs, _ := asn1.Marshal(extraTBS{1, e.TBS.ReportedElements, true})
	raw := e.Raw
	raw.TBS = asn1.RawValue{FullBytes: tbs}
	der, _ := asn1.Marshal(raw)
	if _, err := Parse(der); err == nil {
		t.Fatal("accepted extra TBS field")
	}
	if _, err := Parse(append(der, 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
}

func TestRequiredStructureInMemory(t *testing.T) {
	for _, mutate := range []func(*Evidence){
		func(e *Evidence) { e.Signatures = nil },
		func(e *Evidence) { e.TBS.ReportedElements = nil },
		func(e *Evidence) { e.TBS.ReportedElements[0].Claims = nil },
		func(e *Evidence) { e.Signatures[0].SID = SignerIdentifier{} },
		func(e *Evidence) { e.TBS.ReportedElements[0].Claims[0].Value = asn1.RawValue{} },
		func(e *Evidence) {
			e.TBS.ReportedElements[0].Claims = append(e.TBS.ReportedElements[0].Claims, ReportedClaim{ClaimType: asn1.ObjectIdentifier{1, 2, 3, 4}})
		},
	} {
		e := signedExample(t)
		mutate(e)
		if errs := Validate(e); len(errs) == 0 {
			t.Fatal("accepted missing required structure")
		}
		if VerifyEvidence(e, VerifyOptions{SignatureOnly: true}).Accepted {
			t.Fatal("verification bypassed validation")
		}
	}
}

func TestNoImplicitTrustAndPinnedSPKI(t *testing.T) {
	e := signedExample(t)
	if VerifyEvidence(e, VerifyOptions{}).Accepted {
		t.Fatal("implicitly trusted embedded certificate")
	}
	cert, err := x509.ParseCertificate(rawBytes(e.Signatures[0].SID.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	if res := VerifyEvidence(e, VerifyOptions{TrustedSPKIs: [][]byte{cert.RawSubjectPublicKeyInfo}}); !res.Accepted {
		t.Fatalf("%+v", res)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if res := VerifyEvidence(e, VerifyOptions{Roots: roots}); !res.Accepted {
		t.Fatalf("%+v", res)
	}
}

func TestTBSMutationRejected(t *testing.T) {
	e := signedExample(t)
	e.TBS.Version = 2
	if VerifyEvidence(e, VerifyOptions{SignatureOnly: true}).Accepted {
		t.Fatal("accepted mutated TBS")
	}
}

func TestOpaqueKeyIDResolver(t *testing.T) {
	e := signedExample(t)
	cert, err := x509.ParseCertificate(rawBytes(e.Signatures[0].SID.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	id := []byte("opaque external handle")
	e.Signatures[0].SID = SignerIdentifier{KeyID: id}
	opts := VerifyOptions{TrustedSPKIs: [][]byte{cert.RawSubjectPublicKeyInfo}, ResolveKeyID: func(got []byte) (crypto.PublicKey, *x509.Certificate, error) {
		if !bytes.Equal(got, id) {
			t.Fatal(got)
		}
		return cert.PublicKey, cert, nil
	}}
	if res := VerifyEvidence(e, opts); !res.Accepted {
		t.Fatalf("%+v", res)
	}
	opts.ResolveKeyID = nil
	if res := VerifyEvidence(e, opts); res.Accepted || len(res.Errors) == 0 {
		t.Fatal("unresolved keyId did not reject Evidence")
	}
}

func TestIntegerAndEmptyOctets(t *testing.T) {
	for _, value := range []asn1.RawValue{claimBytes([]byte{}), claimUTF8("")} {
		cv, err := DecodeClaimValue(value)
		if err != nil || cv.Kind == "absent" {
			t.Fatalf("%+v %v", cv, err)
		}
	}
	bigInteger, _ := hex.DecodeString("0209010000000000000000") // 2^64
	var raw asn1.RawValue
	_ = unmarshalExact(bigInteger, &raw)
	cv, err := DecodeClaimValue(raw)
	if err != nil || cv.Integer.String() != "18446744073709551616" {
		t.Fatalf("%+v %v", cv, err)
	}
}

func TestPSSParameters(t *testing.T) {
	defaults, hashFunc, err := parsePSSParams([]byte{0x30, 0x00})
	if err != nil || hashFunc != crypto.SHA1 || defaults.SaltLength != 20 {
		t.Fatalf("bad PSS defaults: %+v %v", defaults, err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hash := pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.RawValue{Tag: asn1.TagNull}}
	hashDER, _ := asn1.Marshal(hash)
	mgf := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}, Parameters: asn1.RawValue{FullBytes: hashDER}}
	type params struct {
		Hash pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
		MGF  pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
		Salt int                      `asn1:"explicit,tag:2"`
	}
	der, _ := asn1.Marshal(params{hash, mgf, 32})
	digest := sha256.Sum256([]byte("signed TBS"))
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	alg := pkix.AlgorithmIdentifier{Algorithm: oidRSASSAPSS, Parameters: asn1.RawValue{FullBytes: der}}
	if err := verifySignature(&key.PublicKey, alg, []byte("signed TBS"), sig); err != nil {
		t.Fatal(err)
	}
	badMGF := mgf
	badMGF.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
	badHash := pkix.AlgorithmIdentifier{Algorithm: oidSHA384}
	badHashDER, _ := asn1.Marshal(badHash)
	mismatchedMGF := mgf
	mismatchedMGF.Parameters = asn1.RawValue{FullBytes: badHashDER}
	for _, p := range []params{{hash, badMGF, 32}, {hash, mismatchedMGF, 32}, {hash, mgf, -1}} {
		invalid, _ := asn1.Marshal(p)
		if _, _, err := parsePSSParams(invalid); err == nil {
			t.Fatal("accepted unsupported PSS parameters")
		}
	}
	if _, _, err := parsePSSParams(nil); err == nil {
		t.Fatal("accepted absent PSS parameters")
	}
	if _, _, err := parsePSSParams(append(der, 0)); err == nil {
		t.Fatal("accepted trailing PSS data")
	}
}

func TestCertificateRequirements(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, err := testCertificate(key, []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := checkAttestationCertificate(cert, nil); err != nil {
		t.Fatal(err)
	}
	copyCert := *cert
	copyCert.KeyUsage = 0
	if checkAttestationCertificate(&copyCert, nil) == nil {
		t.Fatal("accepted missing digitalSignature")
	}
	copyCert = *cert
	copyCert.UnknownExtKeyUsage = nil
	if checkAttestationCertificate(&copyCert, nil) == nil {
		t.Fatal("accepted missing attestation EKU")
	}
}

func TestNonceMismatch(t *testing.T) {
	e := signedExample(t)
	res := VerifyEvidence(e, VerifyOptions{SignatureOnly: true, ExpectedNonce: []byte("other"), CurrentTime: time.Now()})
	if res.Accepted {
		t.Fatal("accepted wrong nonce")
	}
}
