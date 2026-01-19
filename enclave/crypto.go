package enclave

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// HPKE suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
var (
	kemID  = hpke.KEM_X25519_HKDF_SHA256
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_AES128GCM
	suite  = hpke.NewSuite(kemID, kdfID, aeadID)
	info   = []byte("codoh-enclave-v1")
)

// EnclaveKeypair holds the HPKE keypair for the enclave.
type EnclaveKeypair struct {
	PublicKey  kem.PublicKey
	PrivateKey kem.PrivateKey
}

// GenerateKeypair generates a new X25519 keypair for HPKE.
func GenerateKeypair() (*EnclaveKeypair, error) {
	pub, priv, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	return &EnclaveKeypair{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// PublicKeyBytes returns the raw public key bytes (32 bytes for X25519).
func (k *EnclaveKeypair) PublicKeyBytes() ([]byte, error) {
	return k.PublicKey.MarshalBinary()
}

// DecryptBlobB decrypts the encrypted blob B from the client.
// Format: enc (32 bytes) || ciphertext
// Plaintext format: epoch (4) || input (32) || token (32) || query (variable) || kc (32)
func (k *EnclaveKeypair) DecryptBlobB(ciphertext []byte) (*BlobB, error) {
	if len(ciphertext) < 32 {
		return nil, errors.New("ciphertext too short")
	}

	// Create receiver
	receiver, err := suite.NewReceiver(k.PrivateKey, info)
	if err != nil {
		return nil, fmt.Errorf("create receiver: %w", err)
	}

	// enc is the encapsulated key (32 bytes for X25519)
	encSize := kemID.Scheme().CiphertextSize()
	if len(ciphertext) < encSize {
		return nil, errors.New("missing encapsulated key")
	}
	enc := ciphertext[:encSize]
	ct := ciphertext[encSize:]

	// Open the sealed box
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("setup receiver: %w", err)
	}

	plaintext, err := opener.Open(ct, nil) // no AAD
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return parseBlobB(plaintext)
}

// parseBlobB parses the decrypted blob B plaintext.
// Format: epoch (4) || input (32) || token (32) || kc (32) || query (variable)
func parseBlobB(plaintext []byte) (*BlobB, error) {
	// Minimum: 4 + 32 + 32 + 32 + 1 = 101 bytes
	minLen := 4 + 32 + 32 + 32 + 1
	if len(plaintext) < minLen {
		return nil, fmt.Errorf("plaintext too short: %d < %d", len(plaintext), minLen)
	}

	b := &BlobB{}
	offset := 0

	// Epoch (4 bytes, big-endian)
	b.Epoch = binary.BigEndian.Uint32(plaintext[offset : offset+4])
	offset += 4

	// Input (32 bytes)
	b.Input = make([]byte, 32)
	copy(b.Input, plaintext[offset:offset+32])
	offset += 32

	// Token output (32 bytes)
	b.Token = make([]byte, 32)
	copy(b.Token, plaintext[offset:offset+32])
	offset += 32

	// Kc (32 bytes)
	b.Kc = make([]byte, 32)
	copy(b.Kc, plaintext[offset:offset+32])
	offset += 32

	// Query (remaining bytes)
	b.Query = string(plaintext[offset:])

	return b, nil
}

// Decrypt decrypts HPKE-encrypted data using the enclave's private key.
// Format: enc (32 bytes) || ciphertext
// Used for decrypting cache data from target.
func (k *EnclaveKeypair) Decrypt(ciphertext []byte) ([]byte, error) {
	encSize := kemID.Scheme().CiphertextSize()
	if len(ciphertext) < encSize {
		return nil, errors.New("ciphertext too short for enc")
	}

	// Create receiver
	receiver, err := suite.NewReceiver(k.PrivateKey, info)
	if err != nil {
		return nil, fmt.Errorf("create receiver: %w", err)
	}

	enc := ciphertext[:encSize]
	ct := ciphertext[encSize:]

	// Open the sealed box
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("setup receiver: %w", err)
	}

	plaintext, err := opener.Open(ct, nil) // no AAD
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptResponse encrypts a cached DNS response using the client's ephemeral key kc.
// Uses AES-128-GCM with kc as the key.
func EncryptResponse(kc, response []byte) ([]byte, error) {
	if len(kc) != 32 {
		return nil, errors.New("kc must be 32 bytes")
	}

	// Use HPKE's AEAD directly for symmetric encryption
	// Key is 16 bytes for AES-128
	aead, err := aeadID.New(kc[:16])
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, aead.NonceSize())
	// For deterministic caching, we could derive nonce from query hash
	// For now, use zeros (single encryption per kc)
	// In production, use random nonce and prepend to ciphertext

	ciphertext := aead.Seal(nil, nonce, response, nil)

	// Prepend nonce to ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}
