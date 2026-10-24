package evidence

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

func unmarshalExact(data []byte, out interface{}) error {
	rest, err := asn1.Unmarshal(data, out)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("unexpected trailing DER data")
	}
	return nil
}

// sequenceFields rejects extra fields that encoding/asn1 otherwise silently ignores.
func sequenceFields(data []byte, min, max int) ([]asn1.RawValue, error) {
	var seq asn1.RawValue
	if err := unmarshalExact(data, &seq); err != nil {
		return nil, err
	}
	if seq.Class != 0 || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, fmt.Errorf("expected DER SEQUENCE")
	}
	var fields []asn1.RawValue
	rest := seq.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil, err
		}
		if field.Class == 0 && field.Tag == 0 {
			return nil, fmt.Errorf("end-of-contents is not allowed in DER")
		}
		fields = append(fields, field)
	}
	if len(fields) < min || len(fields) > max {
		return nil, fmt.Errorf("unexpected field count: %d (want %d..%d)", len(fields), min, max)
	}
	return fields, nil
}

func checkEvidenceDER(data []byte) error {
	ev, err := sequenceFields(data, 2, 3)
	if err != nil {
		return err
	}
	tbs, err := sequenceFields(ev[0].FullBytes, 2, 2)
	if err != nil {
		return err
	}
	elements, err := sequenceFields(tbs[1].FullBytes, 1, int(^uint(0)>>1))
	if err != nil {
		return err
	}
	for _, element := range elements {
		fields, err := sequenceFields(element.FullBytes, 2, 2)
		if err != nil {
			return err
		}
		claims, err := sequenceFields(fields[1].FullBytes, 1, int(^uint(0)>>1))
		if err != nil {
			return err
		}
		for _, claim := range claims {
			if _, err := sequenceFields(claim.FullBytes, 2, 2); err != nil {
				return err
			}
		}
	}
	sigs, err := sequenceFields(ev[1].FullBytes, 1, int(^uint(0)>>1))
	if err != nil {
		return err
	}
	for _, sig := range sigs {
		fields, err := sequenceFields(sig.FullBytes, 3, 3)
		if err != nil {
			return err
		}
		sid, err := sequenceFields(fields[0].FullBytes, 1, 3)
		if err != nil {
			return err
		}
		previous := -1
		for _, field := range sid {
			if field.Class != 2 || !field.IsCompound || field.Tag > 2 || field.Tag <= previous {
				return fmt.Errorf("invalid SignerIdentifier field")
			}
			previous = field.Tag
			var inner asn1.RawValue
			if err := unmarshalExact(field.Bytes, &inner); err != nil {
				return err
			}
		}
		if _, err := sequenceFields(fields[1].FullBytes, 1, 2); err != nil {
			return err
		}
	}
	if len(ev) == 3 {
		field := ev[2]
		if field.Class != 2 || field.Tag != 0 || !field.IsCompound {
			return fmt.Errorf("invalid intermediateCertificates tag")
		}
		if _, err := sequenceFields(field.Bytes, 0, int(^uint(0)>>1)); err != nil {
			return fmt.Errorf("intermediateCertificates must be EXPLICIT: %w", err)
		}
	}
	return nil
}

// Validate the SPKI syntax without requiring support for its key algorithm.
func validateSPKI(der []byte) error {
	fields, err := sequenceFields(der, 2, 2)
	if err != nil {
		return err
	}
	if _, err := sequenceFields(fields[0].FullBytes, 1, 2); err != nil {
		return err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if err := unmarshalExact(der, &spki); err != nil {
		return err
	}
	for _, oid := range []asn1.ObjectIdentifier{{1, 2, 840, 113549, 1, 1, 1}, {1, 2, 840, 10045, 2, 1}, {1, 3, 101, 112}, {1, 3, 101, 110}, {1, 2, 840, 10040, 4, 1}} {
		if spki.Algorithm.Algorithm.Equal(oid) {
			_, err := x509.ParsePKIXPublicKey(der)
			return err
		}
	}
	return nil
}
