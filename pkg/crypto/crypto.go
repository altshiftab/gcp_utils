package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	gcpUtilsCryptoErrors "github.com/altshiftab/gcp_utils/pkg/crypto/errors"
)

func ParseCertificateMaterial(pemData []byte) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if len(pemData) == 0 {
		return nil, nil, nil
	}

	var key *ecdsa.PrivateKey
	var certificates []*x509.Certificate

	rest := pemData
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		blockType := block.Type
		blockBytes := block.Bytes

		switch blockType {
		case "EC PRIVATE KEY":
			if key != nil {
				return nil, nil, motmedelErrors.MakeErrorWithStackTrace(gcpUtilsCryptoErrors.ErrMultipleCertificateKeys)
			}

			parsedKey, err := x509.ParseECPrivateKey(blockBytes)
			if err != nil {
				return nil, nil, motmedelErrors.MakeErrorWithStackTrace(fmt.Errorf("parse EC private key: %w", err))
			}
			key = parsedKey
		case "CERTIFICATE":
			certificate, err := x509.ParseCertificate(blockBytes)
			if err != nil {
				return nil, nil, motmedelErrors.MakeErrorWithStackTrace(fmt.Errorf("parse certificate: %w", err))
			}
			if certificate == nil {
				continue
			}

			certificates = append(certificates, certificate)
		default:
			return nil, nil, motmedelErrors.MakeErrorWithStackTrace(
				fmt.Sprintf("unexpected block type: %s", blockType),
				blockType,
			)
		}

		rest = remaining
	}

	return key, certificates, nil
}
