package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"key-attestation/go-src/pkg/evidence"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "decode":
		decodeCmd(os.Args[2:])
	case "verify":
		verifyCmd(os.Args[2:])
	case "validate":
		validateCmd(os.Args[2:])
	case "generate":
		generateCmd(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "pkix-evidence: CLI for PKIX Evidence (draft-ietf-rats-pkix-key-attestation)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  pkix-evidence decode   -in <file|-> [-format auto|der|pem|base64]")
	fmt.Fprintln(os.Stderr, "  pkix-evidence verify   -in <file|-> [-format auto|der|pem|base64] [-ca <pem>] [-verify-chain] [-require-all] [-signer-cert <pem>] [-signature-only] [-nonce-hex <hex>]")
	fmt.Fprintln(os.Stderr, "  pkix-evidence validate -in <file|-> [-format auto|der|pem|base64]")
	fmt.Fprintln(os.Stderr, "  pkix-evidence generate -out <file|-> [-format der|pem|base64] [-nonce-hex <hex>] [-key <pem>] [-cert <pem>]")
}

func decodeCmd(args []string) {
	fs := flag.NewFlagSet("decode", flag.ExitOnError)
	inPath := fs.String("in", "-", "input evidence file or - for stdin")
	format := fs.String("format", "auto", "input format: auto|der|pem|base64")
	_ = fs.Parse(args)

	data, err := readInput(*inPath)
	failIf(err)
	der, err := evidence.ReadEvidence(data, *format)
	failIf(err)
	parsed, err := evidence.Parse(der)
	failIf(err)

	out, err := evidence.EvidenceToJSON(parsed)
	failIf(err)
	buf, err := json.MarshalIndent(out, "", "  ")
	failIf(err)
	os.Stdout.Write(buf)
	os.Stdout.Write([]byte("\n"))
}

func validateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	inPath := fs.String("in", "-", "input evidence file or - for stdin")
	format := fs.String("format", "auto", "input format: auto|der|pem|base64")
	_ = fs.Parse(args)

	data, err := readInput(*inPath)
	failIf(err)
	der, err := evidence.ReadEvidence(data, *format)
	failIf(err)
	parsed, err := evidence.Parse(der)
	failIf(err)

	errs := evidence.Validate(parsed)
	if len(errs) == 0 {
		fmt.Fprintln(os.Stdout, "ok")
		return
	}
	for _, e := range errs {
		fmt.Fprintln(os.Stdout, e.Error())
	}
	os.Exit(1)
}

func generateCmd(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	outPath := fs.String("out", "-", "output file or - for stdout")
	format := fs.String("format", "der", "output format: der|pem|base64")
	signed := fs.Bool("signed", true, "generate a signed sample evidence")
	withAKSPKI := fs.Bool("with-ak-spki", true, "deprecated: AK binding is required")
	nonceHex := fs.String("nonce-hex", "", "verifier nonce as hexadecimal bytes")
	keyPath := fs.String("key", "", "PEM private key for signing (optional)")
	certPath := fs.String("cert", "", "PEM signer certificate to embed (optional)")
	_ = fs.Parse(args)

	if !*signed || !*withAKSPKI {
		failIf(fmt.Errorf("unsigned Evidence and omission of ak-spki are not supported"))
	}
	var nonce []byte
	var err error
	if *nonceHex != "" {
		nonce, err = hex.DecodeString(*nonceHex)
		failIf(err)
	}
	var der []byte
	if *signed {
		der, err = evidence.GenerateSampleSigned(evidence.SignOptions{
			WithAKSPKI: *withAKSPKI,
			Nonce:      nonce,
			KeyPath:    *keyPath,
			CertPath:   *certPath,
		})
	} else {
		der, err = evidence.GenerateSample()
	}
	failIf(err)

	out, err := evidence.FormatEvidence(der, *format)
	failIf(err)
	err = writeOutput(*outPath, out)
	failIf(err)
}

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	inPath := fs.String("in", "-", "input evidence file or - for stdin")
	format := fs.String("format", "auto", "input format: auto|der|pem|base64")
	caPath := fs.String("ca", "", "PEM bundle of trust anchors")
	verifyChain := fs.Bool("verify-chain", false, "verify signer certificate chain against -ca")
	requireAll := fs.Bool("require-all", false, "require all signature blocks to verify")
	requireAttestEKU := fs.Bool("require-attest-eku", true, "require attestation EKU on signer certificates")
	attestEKUOID := fs.String("attest-eku-oid", "", "additional accepted attestation EKU OIDs")
	allowedAlgorithms := fs.String("algorithms", "", "comma-separated allowed signature algorithm OIDs")
	signerPath := fs.String("signer-cert", "", "out-of-band signer certificate; pins its SPKI when no CA is supplied")
	signatureOnly := fs.Bool("signature-only", false, "diagnostic signature check without establishing signer trust")
	nonceHex := fs.String("nonce-hex", "", "expected verifier nonce as hexadecimal bytes")
	_ = fs.Parse(args)

	data, err := readInput(*inPath)
	failIf(err)
	der, err := evidence.ReadEvidence(data, *format)
	failIf(err)
	parsed, err := evidence.Parse(der)
	failIf(err)

	ekuOIDs, err := parseOIDList(*attestEKUOID)
	failIf(err)
	if !*requireAttestEKU {
		failIf(fmt.Errorf("Attestation EKU checks cannot be disabled"))
	}

	opts := evidence.VerifyOptions{
		SignatureOnly:         *signatureOnly,
		RequireAllSignatures:  *requireAll,
		VerifyChains:          *verifyChain,
		CurrentTime:           time.Now(),
		RequireAttestationEKU: *requireAttestEKU,
		AttestationEKUOIDs:    ekuOIDs,
	}
	if *verifyChain || *caPath != "" {
		opts.VerifyChains = true
		if *caPath == "" {
			failIf(fmt.Errorf("-verify-chain requires -ca"))
		}
		pool, err := loadCertPool(*caPath)
		failIf(err)
		opts.Roots = pool
	}

	if *signerPath != "" {
		data, err := os.ReadFile(*signerPath)
		failIf(err)
		if block, _ := pem.Decode(data); block != nil {
			data = block.Bytes
		}
		cert, err := x509.ParseCertificate(data)
		failIf(err)
		opts.ResolveKeyID = func(id []byte) (crypto.PublicKey, *x509.Certificate, error) {
			if !bytes.Equal(id, cert.SubjectKeyId) || len(cert.SubjectKeyId) == 0 {
				return nil, nil, fmt.Errorf("keyId does not match configured signer")
			}
			return cert.PublicKey, cert, nil
		}
		if opts.Roots == nil {
			opts.TrustedSPKIs = [][]byte{cert.RawSubjectPublicKeyInfo}
		}
	}
	if *nonceHex != "" {
		opts.ExpectedNonce, err = hex.DecodeString(*nonceHex)
		failIf(err)
	}
	if *allowedAlgorithms != "" {
		opts.AllowedSignatureAlgorithms, err = parseOIDList(*allowedAlgorithms)
		failIf(err)
	}
	res := evidence.VerifyEvidence(parsed, opts)

	for _, r := range res.SignatureResults {
		if r.OK {
			fmt.Fprintf(os.Stdout, "signature[%d]: ok\n", r.Index)
		} else {
			fmt.Fprintf(os.Stdout, "signature[%d]: %s\n", r.Index, r.Error)
		}
	}
	for _, err := range res.Errors {
		fmt.Fprintln(os.Stderr, err)
	}
	if !res.Accepted {
		os.Exit(1)
	}
	if opts.SignatureOnly {
		fmt.Fprintln(os.Stdout, "signature-only: signer trust was not established")
	}
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func writeOutput(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	original := data
	pool := x509.NewCertPool()
	loaded := 0
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
		loaded++
	}
	if loaded == 0 {
		cert, err := x509.ParseCertificate(original)
		if err == nil {
			pool.AddCert(cert)
			loaded++
		}
	}
	if loaded == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

func parseOIDList(value string) ([]asn1.ObjectIdentifier, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		oid, err := parseOID(p)
		if err != nil {
			return nil, err
		}
		out = append(out, oid)
	}
	return out, nil
}

func parseOID(value string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid oid: %s", value)
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("invalid oid: %s", value)
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid oid component %q in %s", p, value)
		}
		oid = append(oid, v)
	}
	return oid, nil
}

func failIf(err error) {
	if err != nil {
		msg := err.Error()
		msg = strings.TrimSpace(msg)
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
}
