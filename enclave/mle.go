package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// MLEBlobBSize is the fixed size of a MLEBlobB plaintext.
// Format: epoch(4) || tag(16) || token_input(32) || token_output(32) || Kc(32) = 116 bytes
const MLEBlobBSize = 4 + 16 + 32 + 32 + 32

// MLEInsertBlobMinSize is the minimum size of an MLEInsertBlob plaintext.
// Format: epoch(4) || tag(16) || exp(8) || sig(64) || ciphertext(1+) = 93+ bytes
const MLEInsertBlobMinSize = 4 + 16 + 8 + 64 + 1

// ParseMLEBlobB parses a decrypted MLEBlobB plaintext.
// Format: epoch(4) || tag(16) || token_input(32) || token_output(32) || Kc(32) = 116 bytes
func ParseMLEBlobB(plaintext []byte) (*MLEBlobB, error) {
	if len(plaintext) != MLEBlobBSize {
		return nil, errors.New("invalid MLEBlobB size")
	}

	b := &MLEBlobB{}
	offset := 0

	// Epoch (4 bytes, big-endian)
	b.Epoch = binary.BigEndian.Uint32(plaintext[offset : offset+4])
	offset += 4

	// Tag (16 bytes)
	copy(b.Tag[:], plaintext[offset:offset+16])
	offset += 16

	// TokenInput (32 bytes)
	b.TokenInput = make([]byte, 32)
	copy(b.TokenInput, plaintext[offset:offset+32])
	offset += 32

	// TokenOutput (32 bytes)
	b.TokenOutput = make([]byte, 32)
	copy(b.TokenOutput, plaintext[offset:offset+32])
	offset += 32

	// Kc (32 bytes)
	b.Kc = make([]byte, 32)
	copy(b.Kc, plaintext[offset:offset+32])

	return b, nil
}

// ParseMLEInsertBlob parses a decrypted MLEInsertBlob plaintext.
// Format: epoch(4) || tag(16) || exp(8) || sig(64) || ciphertext(variable)
func ParseMLEInsertBlob(plaintext []byte) (*MLEInsertBlob, error) {
	if len(plaintext) < MLEInsertBlobMinSize {
		return nil, errors.New("MLEInsertBlob too short")
	}

	b := &MLEInsertBlob{}
	offset := 0

	// Epoch (4 bytes, big-endian)
	b.Epoch = binary.BigEndian.Uint32(plaintext[offset : offset+4])
	offset += 4

	// Tag (16 bytes)
	copy(b.Tag[:], plaintext[offset:offset+16])
	offset += 16

	// Exp (8 bytes, big-endian)
	b.Exp = int64(binary.BigEndian.Uint64(plaintext[offset : offset+8]))
	offset += 8

	// Signature (64 bytes)
	b.Signature = make([]byte, 64)
	copy(b.Signature, plaintext[offset:offset+64])
	offset += 64

	// Ciphertext (remaining bytes)
	b.Ciphertext = make([]byte, len(plaintext)-offset)
	copy(b.Ciphertext, plaintext[offset:])

	return b, nil
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

// WrapMLEResponse wraps an MLE cache entry for the client.
// Encrypts: exp (8 bytes) || ciphertext under Kc using AES-128-GCM.
// Returns: nonce (12 bytes) || encrypted(exp || ciphertext)
func WrapMLEResponse(kc []byte, exp int64, ciphertext []byte) ([]byte, error) {
	if len(kc) < 16 {
		return nil, errors.New("kc must be at least 16 bytes")
	}

	block, err := aes.NewCipher(kc[:16])
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

	// Build plaintext: exp (8 bytes) || ciphertext
	plaintext := make([]byte, 8+len(ciphertext))
	binary.BigEndian.PutUint64(plaintext[:8], uint64(exp))
	copy(plaintext[8:], ciphertext)

	// Encrypt
	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	// Return nonce || sealed
	result := make([]byte, len(nonce)+len(sealed))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], sealed)

	return result, nil
}

// DecryptMLEBlobB decrypts an HPKE-encrypted MLEBlobB.
func (k *EnclaveKeypair) DecryptMLEBlobB(ciphertext []byte) (*MLEBlobB, error) {
	plaintext, err := k.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return ParseMLEBlobB(plaintext)
}

// DecryptMLEInsertBlob decrypts an HPKE-encrypted MLEInsertBlob.
func (k *EnclaveKeypair) DecryptMLEInsertBlob(ciphertext []byte) (*MLEInsertBlob, error) {
	plaintext, err := k.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return ParseMLEInsertBlob(plaintext)
}
