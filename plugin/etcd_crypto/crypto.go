package etcd_crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Type marker for encrypted records (used in TYPE:BASE64 format)
const TypeMarkerAES = "01" // AES-256-GCM encryption (Approach 2: Enclave)

// encryptAES encrypts data using AES-256-GCM
// Returns: [nonce (12 bytes)][ciphertext + auth tag]
func encryptAES(plaintext []byte, key []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM cipher mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and append nonce to the beginning
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// decryptAES decrypts data using AES-256-GCM
// Expects: [nonce (12 bytes)][ciphertext + auth tag]
func decryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM cipher mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum size
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and actual ciphertext
	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// detectAndDecrypt handles the JSON wrapper format and decrypts AES records
// Expected format: {"text": "01:BASE64_CIPHERTEXT", "ttl": 300}
func detectAndDecrypt(data []byte, aesKey []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	// Try parsing as JSON wrapper
	var wrapper map[string]interface{}
	err := json.Unmarshal(data, &wrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON wrapper: %v", err)
	}

	// Check if it's a plaintext A record: {"host": "IP", "ttl": 300}
	if _, hasHost := wrapper["host"]; hasHost {
		// Plaintext record - return as-is
		return data, nil
	}

	// Check if it's an encrypted TXT record: {"text": "TYPE:BASE64", "ttl": 300}
	textVal, hasText := wrapper["text"]
	if !hasText {
		return nil, errors.New("JSON wrapper missing both 'host' and 'text' fields")
	}

	textStr, ok := textVal.(string)
	if !ok {
		return nil, errors.New("'text' field is not a string")
	}

	// Parse TYPE:BASE64 format
	if len(textStr) < 3 || textStr[2] != ':' {
		return nil, fmt.Errorf("invalid TYPE:BASE64 format: expected colon at position 2, got: %s", textStr)
	}

	typeCode := textStr[:2]
	base64Payload := textStr[3:]

	// Check if it's AES type (01)
	if typeCode != TypeMarkerAES {
		return nil, fmt.Errorf("unsupported encryption type: %s (expected %s for AES)", typeCode, TypeMarkerAES)
	}

	// AES encrypted record
	if aesKey == nil {
		return nil, fmt.Errorf("AES key not configured, cannot decrypt type %s record", TypeMarkerAES)
	}

	// Base64 decode the payload
	encryptedBytes, err := base64.StdEncoding.DecodeString(base64Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode payload: %v", err)
	}

	// Decrypt using AES
	return decryptAES(encryptedBytes, aesKey)
}