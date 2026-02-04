package codohtarget

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDeriveMLEKey(t *testing.T) {
	query := "example.com.:1"
	salt := make([]byte, 32)
	rand.Read(salt)

	// Derive key
	key := DeriveMLEKey(query, salt)

	if len(key) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key))
	}

	// Same inputs should produce same output
	key2 := DeriveMLEKey(query, salt)
	if !bytes.Equal(key, key2) {
		t.Error("Same inputs produced different keys")
	}

	// Different query should produce different key
	key3 := DeriveMLEKey("other.com.:1", salt)
	if bytes.Equal(key, key3) {
		t.Error("Different queries produced same key")
	}

	// Different salt should produce different key
	salt2 := make([]byte, 32)
	rand.Read(salt2)
	key4 := DeriveMLEKey(query, salt2)
	if bytes.Equal(key, key4) {
		t.Error("Different salts produced same key")
	}
}

func TestComputeMLETag(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tag := ComputeMLETag(key)

	if len(tag) != 16 {
		t.Errorf("Expected 16-byte tag, got %d bytes", len(tag))
	}

	// Same key should produce same tag
	tag2 := ComputeMLETag(key)
	if tag != tag2 {
		t.Error("Same key produced different tags")
	}

	// Different key should produce different tag
	key2 := make([]byte, 32)
	rand.Read(key2)
	tag3 := ComputeMLETag(key2)
	if tag == tag3 {
		t.Error("Different keys produced same tag")
	}
}

func TestMLEEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("Hello, DNS response!")

	// Encrypt
	ciphertext, err := MLEEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Ciphertext should be larger (nonce + tag overhead)
	if len(ciphertext) <= len(plaintext) {
		t.Errorf("Ciphertext should be larger than plaintext")
	}

	// Decrypt
	decrypted, err := MLEDecrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestMLEEncryptDecryptWrongKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("Secret data")

	// Encrypt with one key
	ciphertext, err := MLEEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with different key
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	_, err = MLEDecrypt(wrongKey, ciphertext)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key")
	}
}

func TestMLEEncryptRandomNonce(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("Same plaintext")

	// Encrypt twice
	ct1, _ := MLEEncrypt(key, plaintext)
	ct2, _ := MLEEncrypt(key, plaintext)

	// Ciphertexts should be different (random nonce)
	if bytes.Equal(ct1, ct2) {
		t.Error("Expected different ciphertexts due to random nonce")
	}

	// But both should decrypt to same plaintext
	pt1, _ := MLEDecrypt(key, ct1)
	pt2, _ := MLEDecrypt(key, ct2)

	if !bytes.Equal(pt1, pt2) {
		t.Error("Decrypted plaintexts don't match")
	}
}

func TestComputeMLESignatureInput(t *testing.T) {
	var tag [16]byte
	copy(tag[:], []byte("0123456789abcdef"))

	epoch := uint32(12345)
	exp := int64(1704067200)
	ciphertext := []byte("encrypted data here")

	input := ComputeMLESignatureInput(epoch, tag, exp, ciphertext)

	if len(input) != 60 {
		t.Errorf("Expected 60-byte signature input, got %d bytes", len(input))
	}

	// Same inputs should produce same output
	input2 := ComputeMLESignatureInput(epoch, tag, exp, ciphertext)
	if !bytes.Equal(input, input2) {
		t.Error("Same inputs produced different signature inputs")
	}

	// Different ciphertext should produce different output (SHA256 changes)
	input3 := ComputeMLESignatureInput(epoch, tag, exp, []byte("different data"))
	if bytes.Equal(input, input3) {
		t.Error("Different ciphertexts produced same signature input")
	}
}

func TestBuildMLEInsertBlob(t *testing.T) {
	var tag [16]byte
	copy(tag[:], []byte("0123456789abcdef"))

	epoch := uint32(12345)
	exp := int64(1704067200)
	signature := make([]byte, 64)
	rand.Read(signature)
	ciphertext := []byte("encrypted DNS response")

	blob := BuildMLEInsertBlob(epoch, tag, exp, signature, ciphertext)

	// Expected size: 4 + 16 + 8 + 64 + len(ciphertext)
	expectedSize := 4 + 16 + 8 + 64 + len(ciphertext)
	if len(blob) != expectedSize {
		t.Errorf("Expected %d bytes, got %d bytes", expectedSize, len(blob))
	}

	// Verify epoch is at the start (big-endian)
	if blob[0] != 0 || blob[1] != 0 || blob[2] != 0x30 || blob[3] != 0x39 {
		t.Errorf("Epoch encoding incorrect: %x", blob[:4])
	}
}

func TestMLEKeyShortKey(t *testing.T) {
	shortKey := make([]byte, 8) // Too short
	rand.Read(shortKey)

	_, err := MLEEncrypt(shortKey, []byte("test"))
	if err == nil {
		t.Error("Expected error with short key")
	}

	_, err = MLEDecrypt(shortKey, []byte("test"))
	if err == nil {
		t.Error("Expected error with short key")
	}
}

func TestMLEDecryptShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	_, err := MLEDecrypt(key, []byte("short"))
	if err == nil {
		t.Error("Expected error with short ciphertext")
	}
}
