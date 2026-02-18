package codohtarget

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

// HPKE suite for enclave communication (must match enclave/crypto.go)
var (
	enclaveKemID  = hpke.KEM_X25519_HKDF_SHA256
	enclaveKdfID  = hpke.KDF_HKDF_SHA256
	enclaveAeadID = hpke.AEAD_AES128GCM
	enclaveSuite  = hpke.NewSuite(enclaveKemID, enclaveKdfID, enclaveAeadID)
	enclaveInfo   = []byte("codoh-enclave-v2")
)

// EncryptForEnclave encrypts data using the enclave's HPKE public key.
// Returns: enc (32 bytes) || ciphertext
func EncryptForEnclave(pubKeyBytes, plaintext []byte) ([]byte, error) {
	// Deserialize public key
	pubKey, err := enclaveKemID.Scheme().UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public key: %w", err)
	}

	// Create sender
	sender, err := enclaveSuite.NewSender(pubKey, enclaveInfo)
	if err != nil {
		return nil, fmt.Errorf("create sender: %w", err)
	}

	// Setup and seal
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("setup sender: %w", err)
	}

	ciphertext, err := sealer.Seal(plaintext, nil) // no AAD
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}

	// Concatenate enc + ciphertext
	result := make([]byte, len(enc)+len(ciphertext))
	copy(result[:len(enc)], enc)
	copy(result[len(enc):], ciphertext)

	return result, nil
}
