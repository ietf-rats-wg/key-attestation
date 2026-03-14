package main

import (
	"crypto/x509"
	"encoding/asn1"
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
	fmt.Fprintln(os.Stderr, "  pkix-evidence verify   -in <file|-> [-format auto|der|pem|base64] [-ca <pem>] [-verify-chain] [-require-all] [-require-attest-eku -attest-eku-oid <oid[,oid...]>]")
	fmt.Fprintln(os.Stderr, "  pkix-evidence validate -in <file|-> [-format auto|der|pem|base64]")
	fmt.Fprintln(os.Stderr, "  pkix-evidence generate -out <file|-> [-format der|pem|base64] [-signed] [-with-ak-spki] [-key <pem>] [-cert <pem>]")
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
	signed := fs.Bool("signed", false, "generate a signed sample evidence")
	withAKSPKI := fs.Bool("with-ak-spki", true, "include transaction.ak-spki when signing")
	keyPath := fs.String("key", "", "PEM private key for signing (optional)")
	certPath := fs.String("cert", "", "PEM signer certificate to embed (optional)")
	_ = fs.Parse(args)

	var der []byte
	var err error
	if *signed {
		der, err = evidence.GenerateSampleSigned(evidence.SignOptions{
			WithAKSPKI: *withAKSPKI,
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
	requireAttestEKU := fs.Bool("require-attest-eku", false, "require attestation EKU on signer certificates")
	attestEKUOID := fs.String("attest-eku-oid", "", "comma-separated attestation EKU OID list")
	_ = fs.Parse(args)

	data, err := readInput(*inPath)
	failIf(err)
	der, err := evidence.ReadEvidence(data, *format)
	failIf(err)
	parsed, err := evidence.Parse(der)
	failIf(err)

	ekuOIDs, err := parseOIDList(*attestEKUOID)
	failIf(err)
	if *requireAttestEKU && len(ekuOIDs) == 0 {
		failIf(fmt.Errorf("-require-attest-eku requires -attest-eku-oid"))
	}

	opts := evidence.VerifyOptions{
		RequireAllSignatures:  *requireAll,
		VerifyChains:          *verifyChain,
		CurrentTime:           time.Now(),
		RequireAttestationEKU: *requireAttestEKU,
		AttestationEKUOIDs:    ekuOIDs,
	}
	if *verifyChain {
		if *caPath == "" {
			failIf(fmt.Errorf("-verify-chain requires -ca"))
		}
		pool, err := loadCertPool(*caPath)
		failIf(err)
		opts.Roots = pool
	}

	res := evidence.VerifyEvidence(parsed, opts)

	okCount := 0
	for _, r := range res.SignatureResults {
		if r.OK {
			okCount++
			fmt.Fprintf(os.Stdout, "signature[%d]: ok\n", r.Index)
		} else {
			fmt.Fprintf(os.Stdout, "signature[%d]: %s\n", r.Index, r.Error)
		}
	}

	for _, err := range res.ChainErrors {
		fmt.Fprintf(os.Stdout, "chain: %s\n", err)
	}
	for _, err := range res.EKUErrors {
		fmt.Fprintf(os.Stdout, "eku: %s\n", err)
	}
	if res.AKSPKIMismatch {
		fmt.Fprintln(os.Stdout, "warning: ak-spki claim does not match all signer SPKIs")
	}

	if len(res.SignatureResults) == 0 {
		fmt.Fprintln(os.Stdout, "warning: evidence is unsigned")
		os.Exit(1)
	}

	if len(res.ChainErrors) > 0 || len(res.EKUErrors) > 0 || res.AKSPKIMismatch {
		os.Exit(1)
	}

	if *requireAll {
		for _, r := range res.SignatureResults {
			if !r.OK {
				os.Exit(1)
			}
		}
	} else if okCount == 0 {
		os.Exit(1)
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
