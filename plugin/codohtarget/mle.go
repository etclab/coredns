package codohtarget

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for MLE key derivation.
// These values change computation time for rate limiting.
const (
	Argon2Memory  = 4 * 1024 // 4 MB
	Argon2Time    = 3         // 3 iterations
	Argon2Threads = 1         // Single thread (predictable timing)
	Argon2KeyLen  = 32        // 32 bytes output
)

// DeriveMLEKey derives a 32-byte MLE key using Argon2id.
// Input: canonicalized query string and epoch salt.
// The expensive computation acts as rate limiting.
func DeriveMLEKey(query string, salt []byte) []byte {
	return argon2.IDKey([]byte(query), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
}

// ComputeMLETag computes a 16-byte tag from the MLE key.
// tag = SHA256(key)[:16]
func ComputeMLETag(key []byte) [16]byte {
	h := sha256.Sum256(key)
	var tag [16]byte
	copy(tag[:], h[:16])
	return tag
}

// MLEEncrypt encrypts plaintext using AES-128-GCM with the MLE key.
// Returns: nonce (12 bytes) || ciphertext+tag
// Uses key[:16] as AES-128 key.
func MLEEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("key must be at least 16 bytes")
	}

	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt: ciphertext includes authentication tag
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Return nonce || ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// MLEDecrypt decrypts ciphertext that was encrypted with MLEEncrypt.
// Input format: nonce (12 bytes) || ciphertext+tag
func MLEDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("key must be at least 16 bytes")
	}

	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ct := ciphertext[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ct, nil)
}

// ComputeMLESignatureInput computes the signature input for MLE cache entries.
// Format: epoch (4 bytes BE) || tag (16 bytes) || exp (8 bytes BE) || SHA256(ciphertext) (32 bytes)
// Total: 60 bytes
func ComputeMLESignatureInput(epoch uint32, tag [16]byte, exp int64, ciphertext []byte) []byte {
	result := make([]byte, 60)
	offset := 0

	// Epoch (4 bytes, big-endian)
	binary.BigEndian.PutUint32(result[offset:], epoch)
	offset += 4

	// Tag (16 bytes)
	copy(result[offset:], tag[:])
	offset += 16

	// Expiry (8 bytes, big-endian)
	binary.BigEndian.PutUint64(result[offset:], uint64(exp))
	offset += 8

	// SHA256(ciphertext) (32 bytes)
	h := sha256.Sum256(ciphertext)
	copy(result[offset:], h[:])

	return result
}

// BuildMLEInsertBlob builds the MLE insert blob for the enclave.
// Format: epoch (4) || tag (16) || exp (8) || sig (64) || ciphertext (variable)
// Total minimum: 92 bytes + ciphertext
func BuildMLEInsertBlob(epoch uint32, tag [16]byte, exp int64, signature, ciphertext []byte) []byte {
	result := make([]byte, 4+16+8+64+len(ciphertext))
	offset := 0

	// Epoch (4 bytes, big-endian)
	binary.BigEndian.PutUint32(result[offset:], epoch)
	offset += 4

	// Tag (16 bytes)
	copy(result[offset:], tag[:])
	offset += 16

	// Expiry (8 bytes, big-endian)
	binary.BigEndian.PutUint64(result[offset:], uint64(exp))
	offset += 8

	// Signature (64 bytes)
	copy(result[offset:], signature[:64])
	offset += 64

	// Ciphertext (variable)
	copy(result[offset:], ciphertext)

	return result
}
