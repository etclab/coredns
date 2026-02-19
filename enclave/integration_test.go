package enclave

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

// TestFullFlow tests the complete CODoH IPC-mode flow:
// Client encrypts Q_E → enclave decrypts (miss) → target builds cache-insert →
// enclave stores → client encrypts Q_E again → enclave decrypts (hit) → client decrypts cached response.
func TestFullFlow(t *testing.T) {
	// --- Setup ---
	keypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	pkBytes, _ := keypair.PublicKeyBytes()
	pkE, err := ParsePublicKeyBytes(pkBytes)
	if err != nil {
		t.Fatalf("ParsePublicKeyBytes: %v", err)
	}

	// Target signing key
	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cache := NewLRUCache(100)
	canonicalQuery := "example.com.:1"
	dnsResponse := []byte{0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05}

	// --- Step 1: Client encrypts Q_E (first request) ---
	qe1, kr1, err := EncryptQueryE(pkE, []byte(canonicalQuery))
	if err != nil {
		t.Fatalf("EncryptQueryE: %v", err)
	}

	// --- Step 2: Enclave decrypts Q_E → cache miss ---
	query1, krEnclave1, err := keypair.DecryptQueryE(qe1)
	if err != nil {
		t.Fatalf("DecryptQueryE: %v", err)
	}
	if string(query1) != canonicalQuery {
		t.Fatalf("query mismatch: got %q, want %q", string(query1), canonicalQuery)
	}
	if !bytes.Equal(kr1, krEnclave1) {
		t.Fatal("k_r mismatch between client and enclave on first request")
	}

	// Cache lookup — should miss (tLatest=0 at startup)
	if _, ok := cache.Get(string(query1), 0); ok {
		t.Fatal("expected cache miss on first request")
	}

	// Enclave returns dummy
	dummy := GenerateDummyResponse(512)
	if len(dummy) != 512 {
		t.Fatalf("dummy size: got %d, want 512", len(dummy))
	}

	// Client tries to decrypt dummy — should fail (AEAD auth failure)
	_, err = DecryptCachedResponse(kr1, dummy)
	if err == nil {
		t.Fatal("expected AEAD auth failure on dummy response")
	}

	// --- Step 3: Target builds cache-insert bundle ---
	bundle := &CacheInsertBundle{
		TTL:            300,
		Timestamp:      time.Now().Unix(),
		CanonicalQuery: canonicalQuery,
		DNSResponse:    dnsResponse,
	}
	bundleBytes := MarshalCacheInsertBundle(bundle)

	// Target HPKE-encrypts bundle to pk_E (using the enclave's HPKE suite directly)
	sender, err := suite.NewSender(pkE, info)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatalf("Setup sender: %v", err)
	}
	ct, err := sealer.Seal(bundleBytes, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	encryptedBlob := make([]byte, len(enc)+len(ct))
	copy(encryptedBlob, enc)
	copy(encryptedBlob[len(enc):], ct)

	// Target signs H(plaintext_bundle)
	hash := sha256.Sum256(bundleBytes)
	sig := ed25519.Sign(sigPriv, hash[:])

	// --- Step 4: Enclave decrypts and stores ---
	plaintext, err := keypair.Decrypt(encryptedBlob)
	if err != nil {
		t.Fatalf("Decrypt cache-insert: %v", err)
	}
	if !bytes.Equal(plaintext, bundleBytes) {
		t.Fatal("decrypted bundle doesn't match original")
	}

	// Verify signature
	if !ed25519.Verify(sigPub, hash[:], sig) {
		t.Fatal("signature verification failed")
	}

	// Parse and store
	parsedBundle, err := ParseCacheInsertBundle(plaintext)
	if err != nil {
		t.Fatalf("ParseCacheInsertBundle: %v", err)
	}
	cache.Put(parsedBundle.CanonicalQuery, parsedBundle.DNSResponse, parsedBundle.Timestamp, parsedBundle.TTL)

	// --- Step 5: Client encrypts Q_E (second request — should hit) ---
	qe2, kr2, err := EncryptQueryE(pkE, []byte(canonicalQuery))
	if err != nil {
		t.Fatalf("EncryptQueryE (2nd): %v", err)
	}

	// --- Step 6: Enclave decrypts Q_E → cache hit ---
	query2, krEnclave2, err := keypair.DecryptQueryE(qe2)
	if err != nil {
		t.Fatalf("DecryptQueryE (2nd): %v", err)
	}
	if string(query2) != canonicalQuery {
		t.Fatalf("query mismatch (2nd): got %q", string(query2))
	}
	if !bytes.Equal(kr2, krEnclave2) {
		t.Fatal("k_r mismatch on second request")
	}

	// Cache hit (use bundle timestamp as tLatest — entry was just inserted)
	cachedResp, ok := cache.Get(string(query2), parsedBundle.Timestamp)
	if !ok {
		t.Fatal("expected cache hit on second request")
	}

	// Encrypt cached response under k_r2
	encrypted, err := EncryptCachedResponse(krEnclave2, cachedResp)
	if err != nil {
		t.Fatalf("EncryptCachedResponse: %v", err)
	}

	// --- Step 7: Client decrypts cached response ---
	decrypted, err := DecryptCachedResponse(kr2, encrypted)
	if err != nil {
		t.Fatalf("DecryptCachedResponse: %v", err)
	}
	if !bytes.Equal(decrypted, dnsResponse) {
		t.Fatalf("decrypted response mismatch: got %x, want %x", decrypted, dnsResponse)
	}

	// Verify k_r1 != k_r2 (different HPKE sessions)
	if bytes.Equal(kr1, kr2) {
		t.Fatal("k_r should differ across HPKE sessions")
	}
}
