package enclave

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestParseMLEBlobB(t *testing.T) {
	// Build a valid MLEBlobB plaintext
	plaintext := make([]byte, MLEBlobBSize)
	offset := 0

	// Epoch (4 bytes, big-endian)
	binary.BigEndian.PutUint32(plaintext[offset:], 12345)
	offset += 4

	// Tag (16 bytes)
	tag := []byte("0123456789abcdef")
	copy(plaintext[offset:], tag)
	offset += 16

	// TokenInput (32 bytes)
	tokenInput := make([]byte, 32)
	rand.Read(tokenInput)
	copy(plaintext[offset:], tokenInput)
	offset += 32

	// TokenOutput (32 bytes)
	tokenOutput := make([]byte, 32)
	rand.Read(tokenOutput)
	copy(plaintext[offset:], tokenOutput)
	offset += 32

	// Kc (32 bytes)
	kc := make([]byte, 32)
	rand.Read(kc)
	copy(plaintext[offset:], kc)

	// Parse
	blob, err := ParseMLEBlobB(plaintext)
	if err != nil {
		t.Fatalf("ParseMLEBlobB failed: %v", err)
	}

	if blob.Epoch != 12345 {
		t.Errorf("Expected epoch 12345, got %d", blob.Epoch)
	}
	if string(blob.Tag[:]) != "0123456789abcdef" {
		t.Errorf("Tag mismatch: %x", blob.Tag)
	}
	if !bytes.Equal(blob.TokenInput, tokenInput) {
		t.Error("TokenInput mismatch")
	}
	if !bytes.Equal(blob.TokenOutput, tokenOutput) {
		t.Error("TokenOutput mismatch")
	}
	if !bytes.Equal(blob.Kc, kc) {
		t.Error("Kc mismatch")
	}
}

func TestParseMLEBlobBInvalidSize(t *testing.T) {
	// Too short
	_, err := ParseMLEBlobB(make([]byte, MLEBlobBSize-1))
	if err == nil {
		t.Error("Expected error for short input")
	}

	// Too long
	_, err = ParseMLEBlobB(make([]byte, MLEBlobBSize+1))
	if err == nil {
		t.Error("Expected error for long input")
	}
}

func TestParseMLEInsertBlob(t *testing.T) {
	// Build a valid MLEInsertBlob plaintext
	ciphertext := []byte("encrypted DNS response data")
	plaintext := make([]byte, 4+16+8+64+len(ciphertext))
	offset := 0

	// Epoch (4 bytes, big-endian)
	binary.BigEndian.PutUint32(plaintext[offset:], 67890)
	offset += 4

	// Tag (16 bytes)
	tag := []byte("fedcba9876543210")
	copy(plaintext[offset:], tag)
	offset += 16

	// Exp (8 bytes, big-endian)
	binary.BigEndian.PutUint64(plaintext[offset:], 1704067200)
	offset += 8

	// Signature (64 bytes)
	signature := make([]byte, 64)
	rand.Read(signature)
	copy(plaintext[offset:], signature)
	offset += 64

	// Ciphertext
	copy(plaintext[offset:], ciphertext)

	// Parse
	blob, err := ParseMLEInsertBlob(plaintext)
	if err != nil {
		t.Fatalf("ParseMLEInsertBlob failed: %v", err)
	}

	if blob.Epoch != 67890 {
		t.Errorf("Expected epoch 67890, got %d", blob.Epoch)
	}
	if string(blob.Tag[:]) != "fedcba9876543210" {
		t.Errorf("Tag mismatch: %x", blob.Tag)
	}
	if blob.Exp != 1704067200 {
		t.Errorf("Expected exp 1704067200, got %d", blob.Exp)
	}
	if !bytes.Equal(blob.Signature, signature) {
		t.Error("Signature mismatch")
	}
	if !bytes.Equal(blob.Ciphertext, ciphertext) {
		t.Error("Ciphertext mismatch")
	}
}

func TestParseMLEInsertBlobTooShort(t *testing.T) {
	_, err := ParseMLEInsertBlob(make([]byte, MLEInsertBlobMinSize-1))
	if err == nil {
		t.Error("Expected error for short input")
	}
}

func TestComputeMLESignatureInput(t *testing.T) {
	var tag [16]byte
	copy(tag[:], []byte("0123456789abcdef"))

	epoch := uint32(12345)
	exp := int64(1704067200)
	ciphertext := []byte("test ciphertext")

	input := ComputeMLESignatureInput(epoch, tag, exp, ciphertext)

	if len(input) != 60 {
		t.Errorf("Expected 60 bytes, got %d", len(input))
	}

	// Verify structure: epoch(4) || tag(16) || exp(8) || hash(32)
	parsedEpoch := binary.BigEndian.Uint32(input[0:4])
	if parsedEpoch != epoch {
		t.Errorf("Epoch mismatch: expected %d, got %d", epoch, parsedEpoch)
	}

	var parsedTag [16]byte
	copy(parsedTag[:], input[4:20])
	if parsedTag != tag {
		t.Error("Tag mismatch in signature input")
	}

	parsedExp := int64(binary.BigEndian.Uint64(input[20:28]))
	if parsedExp != exp {
		t.Errorf("Exp mismatch: expected %d, got %d", exp, parsedExp)
	}

	// Remaining 32 bytes are SHA256(ciphertext)
	// Just verify it's not all zeros
	allZero := true
	for _, b := range input[28:] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Hash portion is all zeros")
	}
}

func TestWrapMLEResponse(t *testing.T) {
	kc := make([]byte, 32)
	rand.Read(kc)

	exp := int64(1704067200)
	ciphertext := []byte("MLE encrypted DNS response")

	wrapped, err := WrapMLEResponse(kc, exp, ciphertext)
	if err != nil {
		t.Fatalf("WrapMLEResponse failed: %v", err)
	}

	// Should be: nonce(12) + encrypted(8 + len(ciphertext) + 16 tag)
	expectedMinSize := 12 + 8 + len(ciphertext) + 16
	if len(wrapped) < expectedMinSize {
		t.Errorf("Wrapped response too short: expected >= %d, got %d", expectedMinSize, len(wrapped))
	}
}

func TestWrapMLEResponseShortKey(t *testing.T) {
	shortKc := make([]byte, 8)
	rand.Read(shortKc)

	_, err := WrapMLEResponse(shortKc, 1704067200, []byte("test"))
	if err == nil {
		t.Error("Expected error with short key")
	}
}

func TestMLESignatureVerification(t *testing.T) {
	// Generate Ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	var tag [16]byte
	copy(tag[:], []byte("0123456789abcdef"))

	epoch := uint32(12345)
	exp := int64(1704067200)
	ciphertext := []byte("encrypted data")

	// Compute signature input
	toSign := ComputeMLESignatureInput(epoch, tag, exp, ciphertext)

	// Sign
	signature := ed25519.Sign(priv, toSign)

	// Verify
	if !ed25519.Verify(pub, toSign, signature) {
		t.Error("Signature verification failed")
	}

	// Verify with tampered data fails
	tamperedToSign := ComputeMLESignatureInput(epoch+1, tag, exp, ciphertext)
	if ed25519.Verify(pub, tamperedToSign, signature) {
		t.Error("Signature should not verify with tampered data")
	}
}
