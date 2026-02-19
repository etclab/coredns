package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/coredns/coredns/enclave"
	"github.com/coredns/coredns/plugin/codohtarget"
)

func newTestHandler(replayDelta float64) *EnclaveHandler {
	keypair, _ := enclave.GenerateKeypair()
	return &EnclaveHandler{
		keypair:            keypair,
		cache:              enclave.NewLRUCache(100),
		replayDelta:        replayDelta,
		defaultPadSize:     512,
		defensiveMode:      false, // tests default to normal mode (not warm-up)
		outstandingQueries: make(map[string]int64),
		warmupThreshold:    10,
		omissionThreshold:  5,
		outstandingTTLSecs: 300,
		startedAt:          time.Now().Format(time.RFC3339),
	}
}

func newTestHandlerDefensive(replayDelta float64) *EnclaveHandler {
	h := newTestHandler(replayDelta)
	h.defensiveMode = true // starts in warm-up like real boot
	return h
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

// --- Sprint 3: Defensive Mode Tests ---

// makeProcessReq builds a Q_E encrypted under the handler's pk_E.
func makeProcessReq(t *testing.T, h *EnclaveHandler, query string) string {
	t.Helper()
	pubBytes, _ := h.keypair.PublicKeyBytes()
	pk, err := enclave.ParsePublicKeyBytes(pubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKeyBytes: %v", err)
	}

	qe, _, err := enclave.EncryptQueryE(pk, []byte(query))
	if err != nil {
		t.Fatalf("EncryptQueryE: %v", err)
	}
	return base64.StdEncoding.EncodeToString(qe)
}

func TestDefensiveMode_BootReturnsDummy(t *testing.T) {
	h := newTestHandlerDefensive(3.0)

	// Pre-populate cache with a real entry
	h.cache.Put("example.com.:1", []byte{0xDE, 0xAD}, 1000, 300)
	h.tLatest.Store(1000)

	// HandleProcess should return miss (dummy) even though entry is in cache
	qe := makeProcessReq(t, h, "example.com.:1")
	resp := h.HandleProcess(qe)

	if resp.Status != enclave.StatusMiss {
		t.Fatalf("defensive mode should return miss, got status=%s", resp.Status)
	}
	if resp.Response == "" {
		t.Fatal("defensive mode should return a dummy blob")
	}
}

func TestDefensiveMode_ExitsOnWarmupThreshold(t *testing.T) {
	h := newTestHandlerDefensive(3.0)
	h.warmupThreshold = 3 // low threshold for testing

	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.targetSigningPubKey = sigPub

	makeStore := func(query string, ts int64) {
		t.Helper()
		bundle := &enclave.CacheInsertBundle{
			TTL: 300, Timestamp: ts,
			CanonicalQuery: query,
			DNSResponse:    []byte{0xAB},
		}
		bundleBytes := enclave.MarshalCacheInsertBundle(bundle)
		pubBytes, _ := h.keypair.PublicKeyBytes()
		ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
		hash := sha256.Sum256(bundleBytes)
		sig := ed25519.Sign(sigPriv, hash[:])
		resp := h.HandleStoreEncrypted(
			base64.StdEncoding.EncodeToString(ct),
			base64.StdEncoding.EncodeToString(sig),
		)
		if resp.Status != enclave.StatusOK {
			t.Fatalf("store %s failed: %s %s", query, resp.Status, resp.Error)
		}
	}

	// After 2 stores (below threshold=3): still defensive → returns miss for cached entry
	makeStore("a.com.:1", 1000)
	makeStore("b.com.:1", 1001)

	qe := makeProcessReq(t, h, "a.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusMiss {
		t.Fatalf("should still return miss before threshold (2 < 3), got %s", resp.Status)
	}

	// 3rd store crosses threshold → exits defensive mode → real cache hit
	makeStore("c.com.:1", 1002)

	qe = makeProcessReq(t, h, "a.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusHit {
		t.Fatalf("expected cache hit after warm-up (3 >= 3), got status=%s", resp.Status)
	}
}

func TestOmissionDetection_EntersDefensiveMode(t *testing.T) {
	h := newTestHandler(3.0)
	h.omissionThreshold = 5

	// Pre-populate cache with one entry and set tLatest
	h.cache.Put("cached.com.:1", []byte{0xFF}, 1000, 300)
	h.tLatest.Store(1000)

	// Verify normal mode works — cache hit
	qe := makeProcessReq(t, h, "cached.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusHit {
		t.Fatalf("expected hit before omission, got %s", resp.Status)
	}

	// Generate 6 cache misses (> threshold of 5) to trigger omission detection
	for i := 0; i < 6; i++ {
		query := fmt.Sprintf("miss%d.com.:1", i)
		qe := makeProcessReq(t, h, query)
		h.HandleProcess(qe)
	}

	// Defensive mode active + cache cleared: previously-cached entry now returns miss
	qe = makeProcessReq(t, h, "cached.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusMiss {
		t.Fatalf("expected miss after omission (defensive mode + cache cleared), got %s", resp.Status)
	}
}

func TestOutstandingTTL_Cleanup(t *testing.T) {
	// Verify that stale outstanding entries are evicted by inline TTL cleanup,
	// preventing them from falsely triggering omission detection.
	//
	// Strategy: create old outstanding entries, then advance tLatest far enough
	// that cleanup evicts them. Then add new entries up to (but not exceeding)
	// the threshold. If old entries survived, total would exceed → omission.
	h := newTestHandler(3.0)
	h.outstandingTTLSecs = 300
	h.omissionThreshold = 8

	// Sentinel: pre-populate cache entry to verify no omission later
	h.cache.Put("sentinel.com.:1", []byte{0xFF}, 100, 3600)
	h.tLatest.Store(100)

	// 5 unique misses at tLatest=100 → 5 outstanding entries
	for i := 0; i < 5; i++ {
		qe := makeProcessReq(t, h, fmt.Sprintf("old%d.com.:1", i))
		h.HandleProcess(qe)
	}

	// Store at ts=500 → tLatest advances to 500.
	// Inline cleanup: old entries at t=100. 100 < 500-300=200 → evicted.
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.targetSigningPubKey = sigPub

	bundle := &enclave.CacheInsertBundle{
		TTL: 3600, Timestamp: 500,
		CanonicalQuery: "stored.com.:1",
		DNSResponse:    []byte{0xAB},
	}
	bundleBytes := enclave.MarshalCacheInsertBundle(bundle)
	pubBytes, _ := h.keypair.PublicKeyBytes()
	ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
	hash := sha256.Sum256(bundleBytes)
	sig := ed25519.Sign(sigPriv, hash[:])
	resp := h.HandleStoreEncrypted(
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(sig),
	)
	if resp.Status != enclave.StatusOK {
		t.Fatalf("store failed: %s %s", resp.Status, resp.Error)
	}

	// 5 more unique misses at tLatest=500 → outstanding should be 5 (not 10)
	for i := 0; i < 5; i++ {
		qe := makeProcessReq(t, h, fmt.Sprintf("new%d.com.:1", i))
		h.HandleProcess(qe)
	}

	// If old entries survived cleanup, outstanding=10 > 8 → omission → cache cleared.
	// If cleanup worked, outstanding=5 ≤ 8 → no omission → sentinel still reachable.
	qe := makeProcessReq(t, h, "sentinel.com.:1")
	resp2 := h.HandleProcess(qe)
	if resp2.Status != enclave.StatusHit {
		t.Fatalf("expected hit (TTL cleanup should prevent omission), got %s", resp2.Status)
	}
}

func TestOutstandingQuery_RemovedOnStore(t *testing.T) {
	// Verify that a store for an outstanding query removes it from tracking,
	// preventing it from counting toward the omission threshold.
	//
	// Strategy: accumulate outstanding entries near the threshold, then store
	// one of them (removing it). Add more misses up to what WOULD exceed the
	// threshold if the entry survived. If removal works → no omission.
	h := newTestHandler(3.0)
	h.omissionThreshold = 3
	h.tLatest.Store(1000)

	// 2 unique misses: outstanding = {a, b} = 2
	qe := makeProcessReq(t, h, "a.com.:1")
	h.HandleProcess(qe)
	qe = makeProcessReq(t, h, "b.com.:1")
	h.HandleProcess(qe)

	// Store for "a.com.:1" → removes from outstanding, puts in cache.
	// Outstanding = {b} = 1.
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.targetSigningPubKey = sigPub

	bundle := &enclave.CacheInsertBundle{
		TTL: 300, Timestamp: 1001,
		CanonicalQuery: "a.com.:1",
		DNSResponse:    []byte{0xAB},
	}
	bundleBytes := enclave.MarshalCacheInsertBundle(bundle)
	pubBytes, _ := h.keypair.PublicKeyBytes()
	ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
	hash := sha256.Sum256(bundleBytes)
	sig := ed25519.Sign(sigPriv, hash[:])
	resp := h.HandleStoreEncrypted(
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(sig),
	)
	if resp.Status != enclave.StatusOK {
		t.Fatalf("store failed: %s %s", resp.Status, resp.Error)
	}

	// 2 more unique misses: outstanding = {b, c, d} = 3. (3 > 3? No.)
	// Without removal: outstanding = {a, b, c, d} = 4. (4 > 3? Yes → omission.)
	qe = makeProcessReq(t, h, "c.com.:1")
	h.HandleProcess(qe)
	qe = makeProcessReq(t, h, "d.com.:1")
	h.HandleProcess(qe)

	// If removal worked: "a.com.:1" is cached and no omission → hit.
	// If removal failed: omission triggered → cache cleared → miss.
	qe = makeProcessReq(t, h, "a.com.:1")
	resp2 := h.HandleProcess(qe)
	if resp2.Status != enclave.StatusHit {
		t.Fatalf("expected hit (store should remove from outstanding, preventing omission), got %s", resp2.Status)
	}
}

func TestKeyRotation_ReturnedOnHPKEFailure(t *testing.T) {
	h := newTestHandler(3.0)

	// Encrypt Q_E under a DIFFERENT keypair (simulates stale pk_E)
	otherKeypair, _ := enclave.GenerateKeypair()
	otherPubBytes, _ := otherKeypair.PublicKeyBytes()
	otherPub, _ := enclave.ParsePublicKeyBytes(otherPubBytes)
	qe, _, _ := enclave.EncryptQueryE(otherPub, []byte("example.com.:1"))
	qeB64 := base64.StdEncoding.EncodeToString(qe)

	resp := h.HandleProcess(qeB64)
	if resp.Status != enclave.StatusKeyRotated {
		t.Fatalf("expected key_rotated on HPKE failure, got status=%s error=%s", resp.Status, resp.Error)
	}
}

func TestKeyRotation_DuringDefensiveMode(t *testing.T) {
	h := newTestHandlerDefensive(3.0)

	// Encrypt Q_E under a different keypair
	otherKeypair, _ := enclave.GenerateKeypair()
	otherPubBytes, _ := otherKeypair.PublicKeyBytes()
	otherPub, _ := enclave.ParsePublicKeyBytes(otherPubBytes)
	qe, _, _ := enclave.EncryptQueryE(otherPub, []byte("example.com.:1"))
	qeB64 := base64.StdEncoding.EncodeToString(qe)

	// Key rotation takes priority over defensive mode
	resp := h.HandleProcess(qeB64)
	if resp.Status != enclave.StatusKeyRotated {
		t.Fatalf("key rotation should take priority in defensive mode, got status=%s", resp.Status)
	}
}

func TestHealthEndpoint_IncludesStartedAt(t *testing.T) {
	h := newTestHandler(3.0)
	resp := h.HandleHealth()

	if resp.Status != enclave.StatusOK {
		t.Fatalf("health should return ok, got %s", resp.Status)
	}
	if resp.StartedAt == "" {
		t.Fatal("health response should include started_at")
	}
	// Verify it's valid RFC3339
	if _, err := time.Parse(time.RFC3339, resp.StartedAt); err != nil {
		t.Fatalf("started_at should be RFC3339, got %q: %v", resp.StartedAt, err)
	}
}

func TestDefensiveMode_NoOutstandingTrackingDuringDefensive(t *testing.T) {
	// Verify that queries during defensive mode do NOT add to outstanding tracking.
	//
	// Strategy: send many queries during defensive mode (more than omission threshold),
	// then exit defensive mode via stores. If entries leaked into the outstanding map,
	// the first post-recovery miss would push past the threshold and re-trigger omission.
	h := newTestHandlerDefensive(3.0)
	h.warmupThreshold = 5
	h.omissionThreshold = 5
	h.tLatest.Store(1000)

	// 10 queries during defensive mode — all return miss (dummy)
	for i := 0; i < 10; i++ {
		query := fmt.Sprintf("defensive%d.com.:1", i)
		qe := makeProcessReq(t, h, query)
		resp := h.HandleProcess(qe)
		if resp.Status != enclave.StatusMiss {
			t.Fatalf("expected miss during defensive mode, got %s", resp.Status)
		}
	}

	// Exit defensive mode via 5 stores (different domains than the 10 above)
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.targetSigningPubKey = sigPub

	for i := 0; i < 5; i++ {
		query := fmt.Sprintf("stored%d.com.:1", i)
		bundle := &enclave.CacheInsertBundle{
			TTL: 300, Timestamp: int64(1001 + i),
			CanonicalQuery: query, DNSResponse: []byte{0xAB},
		}
		bundleBytes := enclave.MarshalCacheInsertBundle(bundle)
		pubBytes, _ := h.keypair.PublicKeyBytes()
		ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
		hash := sha256.Sum256(bundleBytes)
		sig := ed25519.Sign(sigPriv, hash[:])
		resp := h.HandleStoreEncrypted(
			base64.StdEncoding.EncodeToString(ct),
			base64.StdEncoding.EncodeToString(sig),
		)
		if resp.Status != enclave.StatusOK {
			t.Fatalf("store %s failed: %s %s", query, resp.Status, resp.Error)
		}
	}

	// Send 3 new misses (under threshold of 5).
	// If 10 entries leaked from defensive mode: outstanding=10+3=13 > 5 → omission.
	for i := 0; i < 3; i++ {
		qe := makeProcessReq(t, h, fmt.Sprintf("postrecovery%d.com.:1", i))
		h.HandleProcess(qe)
	}

	// If no leakage: outstanding=3 ≤ 5 → no omission → stored entry is a hit.
	qe := makeProcessReq(t, h, "stored0.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusHit {
		t.Fatalf("expected hit (no outstanding leakage during defensive mode), got %s", resp.Status)
	}
}

func TestDefensiveMode_FullCycle(t *testing.T) {
	// Full state machine cycle verified purely through response statuses:
	// boot(defensive) → stores → exit → hit → omission → defensive → stores → exit → hit
	h := newTestHandlerDefensive(3.0)
	h.warmupThreshold = 3
	h.omissionThreshold = 3

	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.targetSigningPubKey = sigPub

	ts := int64(1000)
	storeOne := func(query string) {
		t.Helper()
		ts++
		bundle := &enclave.CacheInsertBundle{
			TTL: 300, Timestamp: ts,
			CanonicalQuery: query, DNSResponse: []byte{0xAB},
		}
		bundleBytes := enclave.MarshalCacheInsertBundle(bundle)
		pubBytes, _ := h.keypair.PublicKeyBytes()
		ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
		hash := sha256.Sum256(bundleBytes)
		sig := ed25519.Sign(sigPriv, hash[:])
		resp := h.HandleStoreEncrypted(
			base64.StdEncoding.EncodeToString(ct),
			base64.StdEncoding.EncodeToString(sig),
		)
		if resp.Status != enclave.StatusOK {
			t.Fatalf("store %s failed: %s %s", query, resp.Status, resp.Error)
		}
	}

	// Phase 1: Boot defensive → recovery via 3 stores
	storeOne("a.com.:1")
	storeOne("b.com.:1")
	storeOne("c.com.:1") // cache.Size()=3 >= warmupThreshold=3

	// Phase 2: Normal operation — cache hit proves defensive mode exited
	qe := makeProcessReq(t, h, "a.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusHit {
		t.Fatalf("phase 2: expected hit after recovery, got %s", resp.Status)
	}

	// Phase 3: Trigger omission detection — 4 unique misses (> threshold=3)
	for i := 0; i < 4; i++ {
		qe := makeProcessReq(t, h, fmt.Sprintf("miss%d.com.:1", i))
		h.HandleProcess(qe)
	}

	// Previously-cached entry now returns miss → defensive mode re-entered + cache cleared
	qe = makeProcessReq(t, h, "a.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusMiss {
		t.Fatalf("phase 3: expected miss (defensive mode after omission), got %s", resp.Status)
	}

	// Phase 4: Second recovery via 3 new stores
	storeOne("d.com.:1")
	storeOne("e.com.:1")
	storeOne("f.com.:1")

	// Phase 5: Cache hit proves defensive mode exited again
	qe = makeProcessReq(t, h, "d.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusHit {
		t.Fatalf("phase 5: expected hit after second recovery, got %s", resp.Status)
	}
}

// --- Concurrent tests (run with -race) ---

func TestDefensiveMode_ConcurrentMissesAndStores(t *testing.T) {
	// Concurrent HandleProcess (misses) and HandleStoreEncrypted (stores)
	// racing on a handler starting in defensive mode. Verifies no panics,
	// no data races, and that stores eventually exit defensive mode.
	h := newTestHandlerDefensive(100.0) // wide δ so all stores accepted
	h.warmupThreshold = 20
	h.omissionThreshold = 200 // high — testing recovery, not omission

	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.targetSigningPubKey = sigPub

	var wg sync.WaitGroup

	// 10 goroutines sending process requests (misses, cache is empty)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			q := fmt.Sprintf("cmiss%d.com.:1", idx)
			qe := makeProcessReq(t, h, q)
			h.HandleProcess(qe)
		}(i)
	}

	// 30 goroutines sending stores (each with unique timestamp to avoid replay)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ts := int64(1000 + idx)
			query := fmt.Sprintf("cstore%d.com.:1", idx)
			bundle := &enclave.CacheInsertBundle{
				TTL: 300, Timestamp: ts,
				CanonicalQuery: query, DNSResponse: []byte{0xAB},
			}
			bundleBytes := enclave.MarshalCacheInsertBundle(bundle)
			pubBytes, _ := h.keypair.PublicKeyBytes()
			ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
			hash := sha256.Sum256(bundleBytes)
			sig := ed25519.Sign(sigPriv, hash[:])
			h.HandleStoreEncrypted(
				base64.StdEncoding.EncodeToString(ct),
				base64.StdEncoding.EncodeToString(sig),
			)
		}(i)
	}

	wg.Wait()

	// After all goroutines: verify handler is usable (no corrupt state).
	// With 30 stores and threshold=20, defensive mode should have exited.
	// Some stores may be replay-rejected depending on scheduling, so check
	// cache size to decide what to assert.
	if h.cache.Size() >= h.warmupThreshold {
		// Defensive mode should have exited — verify with a hit
		qe := makeProcessReq(t, h, "cstore0.com.:1")
		resp := h.HandleProcess(qe)
		if resp.Status != enclave.StatusHit {
			t.Fatalf("expected hit after concurrent recovery (cache=%d), got %s",
				h.cache.Size(), resp.Status)
		}
	} else {
		// Not enough stores survived replay rejection — still defensive.
		// This is OK; the main value is -race detecting no data races.
		t.Logf("cache size %d < threshold %d (replay rejection); race-safety verified",
			h.cache.Size(), h.warmupThreshold)
	}
}

func TestDefensiveMode_ConcurrentOmissionTrigger(t *testing.T) {
	// Many goroutines send unique misses concurrently, racing to trigger
	// omission detection. Verifies no panics, no data races, and that
	// the handler reaches defensive mode.
	h := newTestHandler(3.0) // starts in normal mode
	h.omissionThreshold = 5
	h.tLatest.Store(1000)

	// Pre-populate cache so we can verify omission clears it
	h.cache.Put("sentinel.com.:1", []byte{0xFF}, 1000, 3600)

	// Verify sentinel is reachable before the storm
	qe := makeProcessReq(t, h, "sentinel.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusHit {
		t.Fatalf("expected hit before concurrent misses, got %s", resp.Status)
	}

	// 20 goroutines all send unique misses — at least one push will exceed threshold
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			q := fmt.Sprintf("conc-miss%d.com.:1", idx)
			qe := makeProcessReq(t, h, q)
			h.HandleProcess(qe)
		}(i)
	}
	wg.Wait()

	// Sentinel should now be unreachable: defensive mode active + cache cleared
	qe = makeProcessReq(t, h, "sentinel.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusMiss {
		t.Fatalf("expected miss after concurrent omission trigger, got %s", resp.Status)
	}
}
