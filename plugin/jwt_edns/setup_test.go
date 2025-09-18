package jwt_edns

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/coredns/caddy"
)

// TestSetup tests the various things that should be parsed by setup.
// Make sure you also test for parse errors.
func TestSetup(t *testing.T) {
	// Create a temporary public key for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	tmpfile, err := os.CreateTemp("", "jwt_test_public_*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	if _, err := tmpfile.Write(publicKeyPEM); err != nil {
		t.Fatalf("Failed to write public key: %v", err)
	}

	// Set environment variable for the test
	originalEnv := os.Getenv("JWT_PUBLIC_KEY_PATH")
	os.Setenv("JWT_PUBLIC_KEY_PATH", tmpfile.Name())
	defer os.Setenv("JWT_PUBLIC_KEY_PATH", originalEnv)

	c := caddy.NewTestController("dns", `jwt_edns`)
	if err := setup(c); err == nil {
		t.Fatalf("Expected errors since no algorithm directive is given: %v", err)
	}

	c = caddy.NewTestController("dns", `jwt_edns { invalid_directive }`)
	if err := setup(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}

	// Test valid algorithm directive
	c = caddy.NewTestController("dns", `jwt_edns { algorithm rsa }`)
	if err := setup(c); err != nil {
		t.Fatalf("Expected no errors for valid algorithm, but got: %v", err)
	}

	// Test invalid algorithm
	c = caddy.NewTestController("dns", `jwt_edns { algorithm invalid }`)
	if err := setup(c); err == nil {
		t.Fatalf("Expected errors for invalid algorithm, but got: %v", err)
	}
}
