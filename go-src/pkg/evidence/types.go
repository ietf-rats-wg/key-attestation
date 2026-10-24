package evidence

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

type PkixEvidenceRaw struct {
	TBS                      asn1.RawValue
	Signatures               []SignatureBlock
	IntermediateCertificates []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type TbsEvidence struct {
	Version          int
	ReportedElements []ReportedElement
}

type ReportedElement struct {
	ElementType asn1.ObjectIdentifier
	Claims      []ReportedClaim
}

type ReportedClaim struct {
	ClaimType asn1.ObjectIdentifier
	Value     asn1.RawValue
}

type SignatureBlock struct {
	SID                SignerIdentifier
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     []byte
}

type SignerIdentifier struct {
	KeyID                []byte        `asn1:"optional,explicit,tag:0"`
	SubjectPublicKeyInfo asn1.RawValue `asn1:"optional,explicit,tag:1"`
	Certificate          asn1.RawValue `asn1:"optional,explicit,tag:2"`
}

type Evidence struct {
	TBS                      TbsEvidence
	TBSDER                   []byte
	Signatures               []SignatureBlock
	IntermediateCertificates []*x509.Certificate
	Raw                      PkixEvidenceRaw
}
