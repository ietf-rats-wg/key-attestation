package evidence

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

func parseCertificates(raw []asn1.RawValue) ([]*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]*x509.Certificate, 0, len(raw))
	for _, rv := range raw {
		cert, err := x509.ParseCertificate(rv.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("parse intermediate certificate: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}
