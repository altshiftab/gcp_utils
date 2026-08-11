package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	gcpUtilsCryptoErrors "github.com/altshiftab/gcp_utils/pkg/crypto/errors"
)

func makeKeyPem(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ec private key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})
}

func makeCertificatePem(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certificateDer, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDer})
}

func TestParseCertificateMaterial(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate key: %v", err)
	}

	keyPem := makeKeyPem(t, key)
	certificatePem := makeCertificatePem(t, key)

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		parsedKey, certificates, err := ParseCertificateMaterial(nil)
		if err != nil || parsedKey != nil || certificates != nil {
			t.Errorf("expected all nil, got (%v, %v, %v)", parsedKey, certificates, err)
		}
	})

	t.Run("key and certificate", func(t *testing.T) {
		t.Parallel()

		parsedKey, certificates, err := ParseCertificateMaterial(append(append([]byte{}, keyPem...), certificatePem...))
		if err != nil {
			t.Fatalf("parse certificate material: %v", err)
		}

		if parsedKey == nil || !parsedKey.Equal(key) {
			t.Errorf("key mismatch")
		}
		if len(certificates) != 1 || certificates[0].Subject.CommonName != "test" {
			t.Errorf("certificates: got %v", certificates)
		}
	})

	t.Run("certificates only", func(t *testing.T) {
		t.Parallel()

		parsedKey, certificates, err := ParseCertificateMaterial(append(append([]byte{}, certificatePem...), certificatePem...))
		if err != nil {
			t.Fatalf("parse certificate material: %v", err)
		}

		if parsedKey != nil {
			t.Errorf("unexpected key")
		}
		if len(certificates) != 2 {
			t.Errorf("certificates: got %d", len(certificates))
		}
	})

	t.Run("multiple keys", func(t *testing.T) {
		t.Parallel()

		_, _, err := ParseCertificateMaterial(append(append([]byte{}, keyPem...), keyPem...))
		if !errors.Is(err, gcpUtilsCryptoErrors.ErrMultipleCertificateKeys) {
			t.Errorf("expected multiple certificate keys error, got %v", err)
		}
	})

	t.Run("malformed key block", func(t *testing.T) {
		t.Parallel()

		malformed := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")})
		if _, _, err := ParseCertificateMaterial(malformed); err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("malformed certificate block", func(t *testing.T) {
		t.Parallel()

		malformed := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
		if _, _, err := ParseCertificateMaterial(malformed); err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("unexpected block type", func(t *testing.T) {
		t.Parallel()

		unexpected := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}})
		if _, _, err := ParseCertificateMaterial(unexpected); err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("non-pem data", func(t *testing.T) {
		t.Parallel()

		parsedKey, certificates, err := ParseCertificateMaterial([]byte("not pem"))
		if err != nil || parsedKey != nil || certificates != nil {
			t.Errorf("expected all nil, got (%v, %v, %v)", parsedKey, certificates, err)
		}
	})
}
