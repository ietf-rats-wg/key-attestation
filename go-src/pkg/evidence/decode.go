package evidence

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"
)

func Parse(data []byte) (*Evidence, error) {
	if err := checkEvidenceDER(data); err != nil {
		return nil, err
	}
	var raw PkixEvidenceRaw
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil {
		return nil, fmt.Errorf("asn1 unmarshal pkix evidence: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after pkix evidence (%d bytes)", len(rest))
	}
	if len(raw.TBS.FullBytes) == 0 {
		return nil, errors.New("missing TBS bytes")
	}

	var tbs TbsEvidence
	err = unmarshalExact(raw.TBS.FullBytes, &tbs)
	if err != nil {
		return nil, fmt.Errorf("asn1 unmarshal tbs: %w", err)
	}

	intermediates, err := parseCertificates(raw.IntermediateCertificates)
	if err != nil {
		return nil, err
	}

	return &Evidence{
		TBS:                      tbs,
		TBSDER:                   raw.TBS.FullBytes,
		Signatures:               raw.Signatures,
		IntermediateCertificates: intermediates,
		Raw:                      raw,
	}, nil
}

func ReadEvidence(input []byte, format string) ([]byte, error) {
	if format == "" || format == "auto" {
		if pemBlock, rest := pem.Decode(input); pemBlock != nil {
			if !bytes.HasPrefix(bytes.TrimSpace(input), []byte("-----BEGIN "+pemBlock.Type+"-----")) {
				return nil, errors.New("unexpected data before PEM block")
			}
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, errors.New("trailing PEM data")
			}
			return decodeEvidencePEMBlock(pemBlock)
		}
		trimmed := bytes.TrimSpace(input)
		if looksBase64(trimmed) {
			decoded, err := decodeBase64(trimmed)
			if err == nil {
				return decoded, nil
			}
		}
		return input, nil
	}

	switch format {
	case "pem":
		block, rest := pem.Decode(input)
		if block == nil {
			return nil, errors.New("no PEM block found")
		}
		if !bytes.HasPrefix(bytes.TrimSpace(input), []byte("-----BEGIN "+block.Type+"-----")) {
			return nil, errors.New("unexpected data before PEM block")
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("trailing PEM data")
		}
		return decodeEvidencePEMBlock(block)
	case "base64":
		trimmed := bytes.TrimSpace(input)
		decoded, err := decodeBase64(trimmed)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
		return decoded, nil
	case "der":
		return input, nil
	default:
		return nil, fmt.Errorf("unknown format: %s", format)
	}
}

func decodeBase64(data []byte) ([]byte, error) {
	compact := bytes.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, data)
	return base64.StdEncoding.Strict().DecodeString(string(compact))
}

func decodeEvidencePEMBlock(block *pem.Block) ([]byte, error) {
	if block.Type != "EVIDENCE" {
		return nil, fmt.Errorf("unexpected PEM block type %q, want %q", block.Type, "EVIDENCE")
	}
	return block.Bytes, nil
}

func looksBase64(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		switch {
		case b >= 'A' && b <= 'Z':
		case b >= 'a' && b <= 'z':
		case b >= '0' && b <= '9':
		case b == '+' || b == '/' || b == '=':
		case b == '\n' || b == '\r' || b == '\t' || b == ' ':
		default:
			return false
		}
	}
	return true
}

var canonicalGeneralizedTime = regexp.MustCompile(`^[0-9]{14}(\.[0-9]*[1-9])?Z$`)

// DecodeClaimValue decodes the universal ASN.1 type carried directly by a claim.
func DecodeClaimValue(raw asn1.RawValue) (ClaimValue, error) {
	if !hasRawValue(raw) {
		return ClaimValue{Kind: "absent"}, nil
	}
	der, err := asn1.Marshal(raw)
	if err != nil {
		return ClaimValue{}, err
	}
	var rv asn1.RawValue
	if err := unmarshalExact(der, &rv); err != nil {
		return ClaimValue{}, err
	}
	if rv.Class != asn1.ClassUniversal {
		return ClaimValue{Kind: "unknown", Raw: der}, nil
	}
	cv := ClaimValue{Raw: der}
	switch rv.Tag {
	case asn1.TagOctetString:
		cv.Kind = "bytes"
		err = unmarshalExact(der, &cv.Bytes)
	case asn1.TagUTF8String:
		cv.Kind = "utf8String"
		err = unmarshalExact(der, &cv.String)
	case asn1.TagBoolean:
		cv.Kind = "bool"
		err = unmarshalExact(der, &cv.Bool)
	case asn1.TagGeneralizedTime:
		cv.Kind = "time"
		if !canonicalGeneralizedTime.Match(rv.Bytes) {
			return cv, errors.New("GeneralizedTime must use canonical UTC DER")
		}
		if rv.IsCompound {
			return cv, errors.New("GeneralizedTime must be primitive")
		}
		cv.Time, err = time.Parse("20060102150405Z", string(rv.Bytes))
	case asn1.TagInteger:
		cv.Kind = "int"
		var n *big.Int
		err = unmarshalExact(der, &n)
		if err == nil {
			cv.Integer = n
			if n.IsInt64() {
				cv.Int = n.Int64()
			}
		}
	case asn1.TagSequence:
		cv.Kind = "purposes"
		cv.Bytes = der
		_, err = DecodeCapabilities(der)
	case asn1.TagOID:
		cv.Kind = "oid"
		err = unmarshalExact(der, &cv.OID)
	default:
		cv.Kind = "unknown"
	}
	return cv, err
}

// DecodeClaimValueFor decodes a claim value, using the claim type to tell
// apart claims whose values share the SEQUENCE tag.
func DecodeClaimValueFor(claimType asn1.ObjectIdentifier, raw asn1.RawValue) (ClaimValue, error) {
	isSPKI := claimType.Equal(OIDClaimTransactionAKSPKI) || claimType.Equal(OIDClaimKeySPKI)
	if isSPKI && hasRawValue(raw) {
		der, err := asn1.Marshal(raw)
		if err != nil {
			return ClaimValue{}, err
		}
		var rv asn1.RawValue
		if err := unmarshalExact(der, &rv); err != nil {
			return ClaimValue{}, err
		}
		if rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagSequence {
			return ClaimValue{Kind: "spki", Bytes: der, Raw: der}, nil
		}
	}
	return DecodeClaimValue(raw)
}

func DecodeCapabilities(der []byte) ([]string, error) {
	var oids []asn1.ObjectIdentifier
	err := unmarshalExact(der, &oids)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(oids))
	for _, oid := range oids {
		name, ok := KeyCapabilityNames[oid.String()]
		if !ok {
			name = oid.String()
		}
		out = append(out, name)
	}
	return out, nil
}

func hasRawValue(rv asn1.RawValue) bool {
	return len(rv.FullBytes) > 0 || len(rv.Bytes) > 0 || rv.Tag != 0 || rv.Class != 0 || rv.IsCompound
}

func rawBytes(rv asn1.RawValue) []byte {
	if rv.Class == asn1.ClassContextSpecific {
		return rv.Bytes
	}
	if len(rv.FullBytes) > 0 {
		return rv.FullBytes
	}
	return rv.Bytes
}

func EvidenceToJSON(e *Evidence) (EvidenceJSON, error) {
	out := EvidenceJSON{
		Version: e.TBS.Version,
	}

	for _, element := range e.TBS.ReportedElements {
		e := ElementJSON{
			TypeOID:  element.ElementType.String(),
			TypeName: ElementTypeNames[element.ElementType.String()],
		}
		for _, claim := range element.Claims {
			cspec, ok := ClaimSpecs[claim.ClaimType.String()]
			var cv ClaimValue
			var err error
			if ok {
				cv, err = DecodeClaimValueFor(claim.ClaimType, claim.Value)
			} else {
				cv.Kind = "unknown"
				cv.Raw, err = asn1.Marshal(claim.Value)
			}
			if err != nil {
				return EvidenceJSON{}, err
			}
			c := ClaimJSON{
				TypeOID:   claim.ClaimType.String(),
				TypeName:  cspec.Name,
				ValueKind: cv.Kind,
			}
			switch cv.Kind {
			case "bytes", "spki":
				c.Value = base64.StdEncoding.EncodeToString(cv.Bytes)
			case "purposes":
				c.Capabilities, err = DecodeCapabilities(cv.Bytes)
				if err != nil {
					return EvidenceJSON{}, err
				}
				c.Value = c.Capabilities
			case "utf8String":
				c.Value = cv.String
			case "bool":
				c.Value = cv.Bool
			case "time":
				c.Value = cv.Time.Format(time.RFC3339Nano)
			case "int":
				c.Value = cv.Integer
			case "oid":
				c.Value = cv.OID.String()
			case "null":
				c.Value = nil
			default:
				if len(cv.Raw) > 0 {
					c.Value = base64.StdEncoding.EncodeToString(cv.Raw)
				}
			}
			if ok {
				c.TypeName = cspec.Name
			}
			e.Claims = append(e.Claims, c)
		}
		out.Elements = append(out.Elements, e)
	}

	for _, sig := range e.Signatures {
		b := SignatureJSON{
			SignatureAlgorithmOID: sig.SignatureAlgorithm.Algorithm.String(),
			SignatureValueBase64:  base64.StdEncoding.EncodeToString(sig.SignatureValue),
		}
		if len(sig.SID.KeyID) > 0 {
			b.KeyIDBase64 = base64.StdEncoding.EncodeToString(sig.SID.KeyID)
		}
		if hasRawValue(sig.SID.SubjectPublicKeyInfo) {
			b.SPKIBase64 = base64.StdEncoding.EncodeToString(rawBytes(sig.SID.SubjectPublicKeyInfo))
		}
		if hasRawValue(sig.SID.Certificate) {
			b.CertificateBase64 = base64.StdEncoding.EncodeToString(rawBytes(sig.SID.Certificate))
		}
		out.Signatures = append(out.Signatures, b)
	}

	for _, cert := range e.IntermediateCertificates {
		out.IntermediateCertificates = append(out.IntermediateCertificates, cert.Subject.String())
	}

	return out, nil
}

type ClaimValue struct {
	Kind    string
	Bytes   []byte
	String  string
	Bool    bool
	Time    time.Time
	Int     int64
	Integer *big.Int
	OID     asn1.ObjectIdentifier
	Null    bool
	Raw     []byte
}

type EvidenceJSON struct {
	Version                  int             `json:"version"`
	Elements                 []ElementJSON   `json:"elements"`
	Signatures               []SignatureJSON `json:"signatures"`
	IntermediateCertificates []string        `json:"intermediateCertificates,omitempty"`
}

type ElementJSON struct {
	TypeOID  string      `json:"typeOID"`
	TypeName string      `json:"typeName,omitempty"`
	Claims   []ClaimJSON `json:"claims"`
}

type ClaimJSON struct {
	TypeOID      string      `json:"typeOID"`
	TypeName     string      `json:"typeName,omitempty"`
	ValueKind    string      `json:"valueKind"`
	Value        interface{} `json:"value"`
	Capabilities []string    `json:"capabilities,omitempty"`
}

type SignatureJSON struct {
	SignatureAlgorithmOID string `json:"signatureAlgorithmOID"`
	SignatureValueBase64  string `json:"signatureValueBase64"`
	KeyIDBase64           string `json:"keyIdBase64,omitempty"`
	SPKIBase64            string `json:"spkiBase64,omitempty"`
	CertificateBase64     string `json:"certificateBase64,omitempty"`
}
