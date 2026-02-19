package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/coredns/coredns/enclave"
	"github.com/coredns/coredns/plugin/codohtarget"
)

func newTestHandler(replayDelta float64) *EnclaveHandler {
	keypair, _ := enclave.GenerateKeypair()
	return &EnclaveHandler{
		keypair:     keypair,
		cache:       enclave.NewLRUCache(100),
		replayDelta: replayDelta,
	}
}

// --- validateTimestamp unit tests ---

func TestValidateTimestamp_AcceptsFresh(t *testing.T) {
	h := newTestHandler(3.0)

	// First insert: tLatest=0, ts=1000 → always accepted (1000 < 0-3 is false)
	if err := h.validateTimestamp(1000); err != nil {
		t.Fatalf("expected fresh timestamp accepted, got: %v", err)
	}
	if got := h.tLatest.Load(); got != 1000 {
		t.Fatalf("tLatest should advance to 1000, got %d", got)
	}
}

func TestValidateTimestamp_AcceptsWithinDelta(t *testing.T) {
	h := newTestHandler(3.0)
	h.tLatest.Store(1000)

	// ts=998 → 998 < 1000-3=997? No → accepted
	if err := h.validateTimestamp(998); err != nil {
		t.Fatalf("timestamp within δ should be accepted, got: %v", err)
	}
	// tLatest should NOT advance (998 < 1000)
	if got := h.tLatest.Load(); got != 1000 {
		t.Fatalf("tLatest should stay at 1000, got %d", got)
	}
}

func TestValidateTimestamp_RejectsStale(t *testing.T) {
	h := newTestHandler(3.0)
	h.tLatest.Store(1000)

	// ts=996 → 996 < 1000-3=997? Yes → rejected
	err := h.validateTimestamp(996)
	if err == nil {
		t.Fatal("expected stale timestamp to be rejected")
	}
	if err.Error() != enclave.ErrStaleTimestamp {
		t.Fatalf("expected %q error, got: %v", enclave.ErrStaleTimestamp, err)
	}
}

func TestValidateTimestamp_AdvancesTLatest(t *testing.T) {
	h := newTestHandler(3.0)
	h.tLatest.Store(1000)

	// ts=1005 → accepted and advances tLatest
	if err := h.validateTimestamp(1005); err != nil {
		t.Fatalf("expected accepted, got: %v", err)
	}
	if got := h.tLatest.Load(); got != 1005 {
		t.Fatalf("tLatest should advance to 1005, got %d", got)
	}

	// Now ts=1001 is stale (1001 < 1005-3=1002)
	if err := h.validateTimestamp(1001); err == nil {
		t.Fatal("expected stale rejection after tLatest advanced")
	}
}

func TestValidateTimestamp_BootstrapFromZero(t *testing.T) {
	h := newTestHandler(3.0)
	// tLatest starts at 0

	// Real unix timestamp ~1.7B: should pass (1.7B < 0-3 is false for int64)
	ts := int64(1700000000)
	if err := h.validateTimestamp(ts); err != nil {
		t.Fatalf("bootstrap insert should be accepted, got: %v", err)
	}
	if got := h.tLatest.Load(); got != ts {
		t.Fatalf("tLatest should jump to %d, got %d", ts, got)
	}
}

func TestValidateTimestamp_BoundaryExact(t *testing.T) {
	h := newTestHandler(3.0)
	h.tLatest.Store(1000)

	// ts=997 → 997 < 1000-3=997? No (not strictly less) → accepted
	if err := h.validateTimestamp(997); err != nil {
		t.Fatalf("boundary timestamp (tLatest - δ) should be accepted, got: %v", err)
	}
}

func TestValidateTimestamp_ConcurrentSafety(t *testing.T) {
	h := newTestHandler(3.0)
	h.tLatest.Store(1000)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(ts int64) {
			defer wg.Done()
			_ = h.validateTimestamp(ts)
		}(int64(1000 + i))
	}
	wg.Wait()

	// tLatest should be the max: 1099
	if got := h.tLatest.Load(); got != 1099 {
		t.Fatalf("tLatest should be 1099 after concurrent inserts, got %d", got)
	}
}

// --- HandleStoreEncrypted replay rejection integration test ---

func TestHandleStoreEncrypted_RejectsReplay(t *testing.T) {
	// Generate signing key
	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	h := newTestHandler(3.0)
	h.targetSigningPubKey = sigPub

	// Helper: build an encrypted+signed store_encrypted request
	makeStoreReq := func(query string, ts int64, ttl uint32) (encBlob, sig string) {
		bundle := &enclave.CacheInsertBundle{
			TTL:            ttl,
			Timestamp:      ts,
			CanonicalQuery: query,
			DNSResponse:    []byte{0xAB, 0xCD},
		}
		bundleBytes := enclave.MarshalCacheInsertBundle(bundle)

		// Encrypt to enclave's public key using the target's encrypt helper
		pubBytes, _ := h.keypair.PublicKeyBytes()
		ciphertext, err := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
		if err != nil {
			t.Fatalf("EncryptForEnclave: %v", err)
		}

		// Sign H(plaintext_bundle)
		hash := sha256.Sum256(bundleBytes)
		sigBytes := ed25519.Sign(sigPriv, hash[:])

		return base64.StdEncoding.EncodeToString(ciphertext),
			base64.StdEncoding.EncodeToString(sigBytes)
	}

	tLatest := int64(0)
	expectedResp := []byte{0xAB, 0xCD}

	// Insert 1: ts=1000 → accepted, tLatest advances to 1000
	blob1, sig1 := makeStoreReq("example.com.:1", 1000, 300)
	resp := h.HandleStoreEncrypted(blob1, sig1)
	if resp.Status != enclave.StatusOK {
		t.Fatalf("insert 1 should succeed, got status=%s error=%s", resp.Status, resp.Error)
	}
	tLatest = 1000
	if got := h.tLatest.Load(); got != tLatest {
		t.Fatalf("tLatest should be %d, got %d", tLatest, got)
	}

	// Verify insert 1 is cached and retrievable
	if cached, ok := h.cache.Get("example.com.:1", tLatest); !ok {
		t.Fatal("example.com.:1 should be in cache after accepted insert")
	} else if string(cached) != string(expectedResp) {
		t.Fatalf("cached response mismatch: got %x, want %x", cached, expectedResp)
	}

	// Insert 2: ts=1005 → accepted, tLatest advances to 1005
	blob2, sig2 := makeStoreReq("other.com.:1", 1005, 300)
	resp = h.HandleStoreEncrypted(blob2, sig2)
	if resp.Status != enclave.StatusOK {
		t.Fatalf("insert 2 should succeed, got status=%s error=%s", resp.Status, resp.Error)
	}
	tLatest = 1005

	// Verify insert 2 is cached
	if cached, ok := h.cache.Get("other.com.:1", tLatest); !ok {
		t.Fatal("other.com.:1 should be in cache after accepted insert")
	} else if string(cached) != string(expectedResp) {
		t.Fatalf("cached response mismatch: got %x, want %x", cached, expectedResp)
	}

	// Literal replay: proxy re-sends (blob1, sig1) verbatim after tLatest advanced.
	// This is the actual threat — same ciphertext, same signature, re-delivered.
	// HPKE base-mode decryption succeeds again (no stateful nonce), signature still
	// verifies, so the δ-check must be the thing that catches it.
	// ts=1000 < 1005-3=1002 → REJECTED with stale_timestamp (not decrypt_failed)
	resp = h.HandleStoreEncrypted(blob1, sig1)
	if resp.Status != enclave.StatusError {
		t.Fatalf("literal replay should be rejected, got status=%s", resp.Status)
	}
	if resp.Error != enclave.ErrStaleTimestamp {
		t.Fatalf("literal replay must fail on stale_timestamp (not %s) — "+
			"confirms δ-check catches it, not HPKE stateful rejection", resp.Error)
	}

	// Insert 3: ts=1003 → 1003 < 1005-3=1002? No → accepted (within δ window)
	blob3, sig3 := makeStoreReq("recent.com.:1", 1003, 300)
	resp = h.HandleStoreEncrypted(blob3, sig3)
	if resp.Status != enclave.StatusOK {
		t.Fatalf("insert within δ should succeed, got status=%s error=%s", resp.Status, resp.Error)
	}

	// Verify insert 4 is cached
	if cached, ok := h.cache.Get("recent.com.:1", tLatest); !ok {
		t.Fatal("recent.com.:1 should be in cache after accepted insert within δ")
	} else if string(cached) != string(expectedResp) {
		t.Fatalf("cached response mismatch: got %x, want %x", cached, expectedResp)
	}

	// Verify earlier accepted entries are still retrievable
	if _, ok := h.cache.Get("example.com.:1", tLatest); !ok {
		t.Fatal("example.com.:1 should still be in cache")
	}
	if _, ok := h.cache.Get("other.com.:1", tLatest); !ok {
		t.Fatal("other.com.:1 should still be in cache")
	}
}
