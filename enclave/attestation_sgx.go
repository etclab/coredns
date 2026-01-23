//go:build ego

package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/edgelesssys/ego/enclave"
)

// getRemoteReport generates an SGX DCAP quote with user data.
// This is only available when running inside an EGo enclave.
func getRemoteReport(userData []byte) ([]byte, error) {
	return enclave.GetRemoteReport(userData)
}

// getAttestedTLSConfig returns EGo's attested TLS configuration.
// The TLS certificate is bound to the SGX enclave via attestation.
func getAttestedTLSConfig() (*tls.Config, error) {
	return enclave.CreateAttestationServerTLSConfig()
}

// generateSelfSignedTLSConfig creates a self-signed TLS config as fallback.
// In SGX mode, this should rarely be needed as attested TLS is preferred.
func generateSelfSignedTLSConfig() (*tls.Config, error) {
	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"CODoH Enclave"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}
