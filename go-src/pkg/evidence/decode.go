package evidence

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

func Parse(data []byte) (*Evidence, error) {
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

	var tbs TbsPkixEvidence
	_, err = asn1.Unmarshal(raw.TBS.FullBytes, &tbs)
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
		if pemBlock, _ := pem.Decode(input); pemBlock != nil {
			return pemBlock.Bytes, nil
		}
		trimmed := bytes.TrimSpace(input)
		if looksBase64(trimmed) {
			decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
			if err == nil {
				return decoded, nil
			}
		}
		return input, nil
	}

	switch format {
	case "pem":
		block, _ := pem.Decode(input)
		if block == nil {
			return nil, errors.New("no PEM block found")
		}
		return block.Bytes, nil
	case "base64":
		trimmed := bytes.TrimSpace(input)
		decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
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

func DecodeClaimValue(raw asn1.RawValue) (ClaimValue, error) {
	if len(raw.FullBytes) == 0 && len(raw.Bytes) == 0 {
		return ClaimValue{Kind: "absent"}, nil
	}
	if raw.Class != asn1.ClassContextSpecific {
		return ClaimValue{Kind: "unknown", Raw: raw.FullBytes}, nil
	}

	switch raw.Tag {
	case 0:
		return ClaimValue{Kind: "bytes", Bytes: append([]byte(nil), raw.Bytes...)}, nil
	case 1:
		return ClaimValue{Kind: "utf8String", String: string(raw.Bytes)}, nil
	case 2:
		if len(raw.Bytes) != 1 {
			return ClaimValue{Kind: "bool"}, fmt.Errorf("invalid bool length %d", len(raw.Bytes))
		}
		return ClaimValue{Kind: "bool", Bool: raw.Bytes[0] != 0}, nil
	case 3:
		var t time.Time
		if _, err := asn1.Unmarshal(wrapUniversal(asn1.TagGeneralizedTime, raw.Bytes), &t); err != nil {
			return ClaimValue{Kind: "time"}, err
		}
		return ClaimValue{Kind: "time", Time: t}, nil
	case 4:
		var i int64
		if _, err := asn1.Unmarshal(wrapUniversal(asn1.TagInteger, raw.Bytes), &i); err != nil {
			return ClaimValue{Kind: "int"}, err
		}
		return ClaimValue{Kind: "int", Int: i}, nil
	case 5:
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(wrapUniversal(asn1.TagOID, raw.Bytes), &oid); err != nil {
			return ClaimValue{Kind: "oid"}, err
		}
		return ClaimValue{Kind: "oid", OID: oid}, nil
	case 6:
		return ClaimValue{Kind: "null", Null: true}, nil
	default:
		return ClaimValue{Kind: "unknown", Raw: raw.FullBytes}, nil
	}
}

func wrapUniversal(tag int, content []byte) []byte {
	length := len(content)
	var header []byte
	if length < 128 {
		header = []byte{byte(tag), byte(length)}
	} else {
		lenBytes := encodeLength(length)
		header = append([]byte{byte(tag), byte(0x80 | len(lenBytes))}, lenBytes...)
	}
	return append(header, content...)
}

func encodeLength(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n & 0xff)}, out...)
		n >>= 8
	}
	return out
}

func DecodeCapabilities(der []byte) ([]string, error) {
	var oids []asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(der, &oids)
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
	return len(rv.FullBytes) > 0 || len(rv.Bytes) > 0
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

	for _, entity := range e.TBS.ReportedEntities {
		e := EntityJSON{
			TypeOID:  entity.EntityType.String(),
			TypeName: EntityTypeNames[entity.EntityType.String()],
		}
		for _, claim := range entity.ClaimSet {
			cv, err := DecodeClaimValue(claim.Value)
			if err != nil {
				return EvidenceJSON{}, err
			}
			cspec, ok := ClaimSpecs[claim.ClaimType.String()]
			c := ClaimJSON{
				TypeOID:   claim.ClaimType.String(),
				TypeName:  cspec.Name,
				ValueKind: cv.Kind,
			}
			switch cv.Kind {
			case "bytes":
				c.Value = base64.StdEncoding.EncodeToString(cv.Bytes)
				if claim.ClaimType.Equal(OIDClaimKeyPurpose) {
					caps, err := DecodeCapabilities(cv.Bytes)
					if err == nil {
						c.Capabilities = caps
					}
				}
			case "utf8String":
				c.Value = cv.String
			case "bool":
				c.Value = cv.Bool
			case "time":
				c.Value = cv.Time.Format(time.RFC3339)
			case "int":
				c.Value = cv.Int
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
		out.Entities = append(out.Entities, e)
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
	Kind   string
	Bytes  []byte
	String string
	Bool   bool
	Time   time.Time
	Int    int64
	OID    asn1.ObjectIdentifier
	Null   bool
	Raw    []byte
}

type EvidenceJSON struct {
	Version                  int             `json:"version"`
	Entities                 []EntityJSON    `json:"entities"`
	Signatures               []SignatureJSON `json:"signatures"`
	IntermediateCertificates []string        `json:"intermediateCertificates,omitempty"`
}

type EntityJSON struct {
	TypeOID  string      `json:"typeOID"`
	TypeName string      `json:"typeName,omitempty"`
	Claims   []ClaimJSON `json:"claims"`
}

type ClaimJSON struct {
	TypeOID      string      `json:"typeOID"`
	TypeName     string      `json:"typeName,omitempty"`
	ValueKind    string      `json:"valueKind"`
	Value        interface{} `json:"value,omitempty"`
	Capabilities []string    `json:"capabilities,omitempty"`
}

type SignatureJSON struct {
	SignatureAlgorithmOID string `json:"signatureAlgorithmOID"`
	SignatureValueBase64  string `json:"signatureValueBase64"`
	KeyIDBase64           string `json:"keyIdBase64,omitempty"`
	SPKIBase64            string `json:"spkiBase64,omitempty"`
	CertificateBase64     string `json:"certificateBase64,omitempty"`
}
