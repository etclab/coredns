package codohtarget

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
)

// SigningKey holds Ed25519 keypair for signing target responses.
type SigningKey struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// LoadOrGenerateSigningKey loads an Ed25519 signing key from path,
// or generates a new one if the file doesn't exist.
func LoadOrGenerateSigningKey(path string) (*SigningKey, error) {
	// Try to load existing key
	data, err := os.ReadFile(path)
	if err == nil {
		return parseSigningKey(data)
	}

	if !os.IsNotExist(err) {
		return nil, err
	}

	// Generate new key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Save to file
	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(), // Save only seed (32 bytes)
	}
	pemData := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		return nil, err
	}

	return &SigningKey{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// parseSigningKey parses a PEM-encoded Ed25519 private key.
func parseSigningKey(data []byte) (*SigningKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "ED25519 PRIVATE KEY" {
		return nil, errors.New("unexpected PEM block type: " + block.Type)
	}

	if len(block.Bytes) != ed25519.SeedSize {
		return nil, errors.New("invalid Ed25519 seed size")
	}

	priv := ed25519.NewKeyFromSeed(block.Bytes)
	pub := priv.Public().(ed25519.PublicKey)

	return &SigningKey{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// Sign signs data with the Ed25519 private key.
func (s *SigningKey) Sign(data []byte) []byte {
	return ed25519.Sign(s.PrivateKey, data)
}

// PublicKeyBytes returns the raw public key bytes (32 bytes).
func (s *SigningKey) PublicKeyBytes() []byte {
	return s.PublicKey
}

