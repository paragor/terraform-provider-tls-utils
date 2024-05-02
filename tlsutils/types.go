package tlsutils

import (
	"encoding/pem"
	"fmt"
)

// Algorithm represents a type of private key algorithm.
type Algorithm string

const (
	RSA     Algorithm = "RSA"
	ECDSA   Algorithm = "ECDSA"
	ED25519 Algorithm = "ED25519"
)

func (a Algorithm) String() string {
	return string(a)
}

// supportedAlgorithms returns a slice of Algorithm currently supported by this provider.
func supportedAlgorithms() []Algorithm {
	return []Algorithm{
		RSA,
		ECDSA,
		ED25519,
	}
}

// ECDSACurve represents a type of ECDSA elliptic curve.
type ECDSACurve string

const (
	P224 ECDSACurve = "P224"
	P256 ECDSACurve = "P256"
	P384 ECDSACurve = "P384"
	P521 ECDSACurve = "P521"
)

func (e ECDSACurve) String() string {
	return string(e)
}

// supportedECDSACurves returns an array of ECDSACurve currently supported by this provider.
func supportedECDSACurves() []ECDSACurve {
	return []ECDSACurve{
		P224,
		P256,
		P384,
		P521,
	}
}

// supportedECDSACurvesStr returns the same content of supportedECDSACurves but as a slice of string.
func supportedECDSACurvesStr() []string {
	supported := supportedECDSACurves()
	supportedStr := make([]string, len(supported))
	for i := range supported {
		supportedStr[i] = supported[i].String()
	}
	return supportedStr
}

// PEMPreamble represents the heading used in a PEM-formatted for the "encapsulation boundaries",
// that is used to delimit the "encapsulated text portion" of cryptographic documents.
//
// See https://datatracker.ietf.org/doc/html/rfc1421 and https://datatracker.ietf.org/doc/html/rfc7468.
type PEMPreamble string

const (
	PreamblePublicKey PEMPreamble = "PUBLIC KEY"

	PreamblePrivateKeyPKCS8   PEMPreamble = "PRIVATE KEY"
	PreamblePrivateKeyRSA     PEMPreamble = "RSA PRIVATE KEY"
	PreamblePrivateKeyEC      PEMPreamble = "EC PRIVATE KEY"
	PreamblePrivateKeyOpenSSH PEMPreamble = "OPENSSH PRIVATE KEY"

	PreambleCertificate        PEMPreamble = "CERTIFICATE"
	PreambleCertificateRequest PEMPreamble = "CERTIFICATE REQUEST"

	PreambleCRL PEMPreamble = "X509 CRL"
)

func (p PEMPreamble) String() string {
	return string(p)
}

// pemBlockToPEMPreamble takes a pem.Block and returns the related PEMPreamble, if supported.
func pemBlockToPEMPreamble(block *pem.Block) (PEMPreamble, error) {
	switch block.Type {
	case PreamblePublicKey.String():
		return PreamblePublicKey, nil
	case PreamblePrivateKeyPKCS8.String():
		return PreamblePrivateKeyPKCS8, nil
	case PreamblePrivateKeyRSA.String():
		return PreamblePrivateKeyRSA, nil
	case PreamblePrivateKeyEC.String():
		return PreamblePrivateKeyEC, nil
	case PreambleCertificate.String():
		return PreambleCertificate, nil
	case PreambleCertificateRequest.String():
		return PreambleCertificateRequest, nil
	case PreambleCRL.String():
		return PreambleCRL, nil
	default:
		return "", fmt.Errorf("unsupported PEM preamble/type: %s", block.Type)
	}
}
