package tlsutils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func parsePEMCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse private certificate")
	}

	preamble, err := pemBlockToPEMPreamble(block)
	if err != nil {
		return nil, fmt.Errorf("failed to identify PEM preamble: %w", err)
	}

	if preamble != PreambleCertificate {
		return nil, fmt.Errorf("certificate PEM should be %q, got %q", PreambleCertificate, preamble)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %w", err)
	}

	return cert, nil
}
