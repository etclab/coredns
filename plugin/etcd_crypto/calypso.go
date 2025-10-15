package etcd_crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/calypso"
	"github.com/etclab/ncircl/hibe/akn07"
	"github.com/miekg/dns"
)

// CalypsoKey holds Calypso public parameters and private key for decryption
type CalypsoKey struct {
	PublicParams *akn07.PublicParams
	PrivateKey   *calypso.PrivateKey
}

// deserializeCalypsoPrivateKey deserializes a Calypso PrivateKey from gob encoding
func deserializeCalypsoPrivateKey(data []byte) (*calypso.PrivateKey, error) {
	key := &calypso.PrivateKey{}
	buf := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(key); err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	return key, nil
}

// deserializeCalypsoSignature deserializes bytes to an akn07.Signature
// Format: [S0_len(4)|S0_bytes|S1_len(4)|S1_bytes]
func deserializeCalypsoSignature(data []byte) (*akn07.Signature, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("signature data too short")
	}

	offset := 0
	s0Len := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(s0Len) > len(data) {
		return nil, fmt.Errorf("invalid S0 length")
	}

	s0 := new(bls.G1)
	if err := s0.SetBytes(data[offset : offset+int(s0Len)]); err != nil {
		return nil, fmt.Errorf("failed to deserialize S0: %w", err)
	}
	offset += int(s0Len)

	if offset+4 > len(data) {
		return nil, fmt.Errorf("signature data too short for S1 length")
	}
	s1Len := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(s1Len) != len(data) {
		return nil, fmt.Errorf("invalid S1 length")
	}

	s1 := new(bls.G2)
	if err := s1.SetBytes(data[offset : offset+int(s1Len)]); err != nil {
		return nil, fmt.Errorf("failed to deserialize S1: %w", err)
	}

	return &akn07.Signature{S0: s0, S1: s1}, nil
}

// deserializeCalypsoMessage deserializes bytes to a Calypso Message
// Format: [version(1)|SearchTag_len(2)|SearchTag|WrappedKey_len(4)|WrappedKey|
//          IV_len(2)|IV|Ciphertext_len(4)|Ciphertext|Signature_len(4)|Signature]
func deserializeCalypsoMessage(data []byte) (*calypso.Message, error) {
	if len(data) < 1+2+4+2+4+4 {
		return nil, fmt.Errorf("message data too short")
	}

	offset := 0

	// Version
	version := data[offset]
	offset++
	if version != 1 {
		return nil, fmt.Errorf("unsupported message version: %d", version)
	}

	// SearchTag
	searchTagLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(searchTagLen) > len(data) {
		return nil, fmt.Errorf("invalid SearchTag length")
	}
	searchTag := string(data[offset : offset+int(searchTagLen)])
	offset += int(searchTagLen)

	// WrappedKey
	if offset+4 > len(data) {
		return nil, fmt.Errorf("message data too short for WrappedKey length")
	}
	wrappedKeyLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(wrappedKeyLen) > len(data) {
		return nil, fmt.Errorf("invalid WrappedKey length")
	}
	wrappedKey := &akn07.Ciphertext{}
	if err := wrappedKey.UnmarshalBinary(data[offset : offset+int(wrappedKeyLen)]); err != nil {
		return nil, fmt.Errorf("failed to deserialize WrappedKey: %w", err)
	}
	offset += int(wrappedKeyLen)

	// IV
	if offset+2 > len(data) {
		return nil, fmt.Errorf("message data too short for IV length")
	}
	ivLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(ivLen) > len(data) {
		return nil, fmt.Errorf("invalid IV length")
	}
	iv := data[offset : offset+int(ivLen)]
	offset += int(ivLen)

	// Ciphertext
	if offset+4 > len(data) {
		return nil, fmt.Errorf("message data too short for Ciphertext length")
	}
	ciphertextLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(ciphertextLen) > len(data) {
		return nil, fmt.Errorf("invalid Ciphertext length")
	}
	ciphertext := data[offset : offset+int(ciphertextLen)]
	offset += int(ciphertextLen)

	// Signature
	if offset+4 > len(data) {
		return nil, fmt.Errorf("message data too short for Signature length")
	}
	sigLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(sigLen) != len(data) {
		return nil, fmt.Errorf("invalid Signature length")
	}
	signature, err := deserializeCalypsoSignature(data[offset : offset+int(sigLen)])
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Signature: %w", err)
	}

	return &calypso.Message{
		SearchTag:  searchTag,
		WrappedKey: wrappedKey,
		IV:         iv,
		Ciphertext: ciphertext,
		Signature:  signature,
	}, nil
}

// etcdKeyToDomain converts an etcd key path to a domain name.
// Example: "/skydns/com/example/www" -> "www.example.com"
// NOTE: Currently unused - kept for potential debugging/logging use.
// With search tag storage, domain comes from CalypsoKey.PrivateKey.DomainName instead.
func etcdKeyToDomain(etcdKey string, pathPrefix string) (string, error) {
	// Remove path prefix (e.g., "/skydns")
	if !strings.HasPrefix(etcdKey, pathPrefix) {
		return "", fmt.Errorf("etcd key %q does not start with path prefix %q", etcdKey, pathPrefix)
	}

	// Remove prefix and leading slash
	domain := strings.TrimPrefix(etcdKey, pathPrefix)
	domain = strings.TrimPrefix(domain, "/")

	if domain == "" {
		return "", fmt.Errorf("empty domain after removing prefix")
	}

	// Split into labels and reverse: "com/example/www" -> ["com", "example", "www"] -> "www.example.com"
	labels := strings.Split(domain, "/")

	// Reverse the labels
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}

	// Join with dots
	return strings.Join(labels, "."), nil
}

// decryptCalypso decrypts a Calypso encrypted record.
// The ciphertext is a serialized calypso.Message (already stripped of type marker).
// Calypso performs both decryption AND signature verification via DecryptAndVerify.
// The domain parameter is the concrete domain name being queried (extracted from etcd key).
func decryptCalypso(ciphertext []byte, calypsoKey *CalypsoKey, domain string) ([]byte, error) {
	if calypsoKey == nil {
		return nil, fmt.Errorf("Calypso key not configured")
	}
	if calypsoKey.PublicParams == nil || calypsoKey.PrivateKey == nil {
		return nil, fmt.Errorf("Calypso public params or private key is nil")
	}

	// 1. Deserialize Message
	message, err := deserializeCalypsoMessage(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("message deserialization failed: %w", err)
	}

	// 2. Decrypt and verify signature using Calypso
	// CRITICAL: domain must be the concrete domain that was encrypted/signed
	// Signature verification will fail if domain doesn't match what the writer used
	plaintext, err := calypsoKey.PrivateKey.DecryptAndVerify(domain, message)
	if err != nil {
		return nil, fmt.Errorf("DecryptAndVerify failed (signature may be invalid): %w", err)
	}

	return plaintext, nil
}

// domainToPattern converts a DNS domain to a WKD-IBE/Calypso pattern
// Example: "alice.example.com" with maxDepth=5 → ["com", "example", "alice", "", ""]
func domainToPattern(domain string, maxDepth int) ([]string, error) {
	if maxDepth < 2 {
		return nil, fmt.Errorf("maxDepth must be at least 2")
	}

	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	parts := dns.SplitDomainName(domain)
	if len(parts) > maxDepth-1 {
		return nil, fmt.Errorf("domain exceeds maxDepth capacity")
	}

	pattern := make([]string, maxDepth)

	// Reverse domain parts (alice.example.com → com, example, alice)
	for i := 0; i < len(parts); i++ {
		reversedIdx := len(parts) - 1 - i
		part := parts[reversedIdx]

		if part == "" {
			return nil, fmt.Errorf("invalid pattern: empty labels not allowed")
		}
		pattern[i] = part
	}

	// Remaining slots are padding (empty strings for unused positions)
	return pattern, nil
}

// computeSearchTag derives SHA256 hash of domain pattern for privacy-preserving etcd storage
// Example: "alice.example.com" → ["com", "example", "alice"] → SHA256 → hex string
// Only concrete pattern values are hashed (empty padding slots excluded)
func computeSearchTag(domain string, maxDepth int) (string, error) {
	// Convert domain to pattern
	pattern, err := domainToPattern(domain, maxDepth)
	if err != nil {
		return "", fmt.Errorf("failed to convert domain to pattern: %w", err)
	}

	// Extract only concrete (non-empty) pattern components
	var concrete []string
	for _, part := range pattern {
		if part != "" {
			concrete = append(concrete, part)
		}
	}

	if len(concrete) == 0 {
		return "", fmt.Errorf("pattern has no concrete components")
	}

	// Hash the concrete pattern components
	// Join with null byte separator to prevent collision (e.g., ["a","bc"] vs ["ab","c"])
	patternStr := strings.Join(concrete, "\x00")
	hash := sha256.Sum256([]byte(patternStr))

	// Return hex-encoded hash
	return hex.EncodeToString(hash[:]), nil
}