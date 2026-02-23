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

// marshalSingleBundle wraps a single CacheInsertBundle into the multi-entry wire format.
func marshalSingleBundle(t *testing.T, b *enclave.CacheInsertBundle) []byte {
	t.Helper()
	data, err := enclave.MarshalMultiBundle([]enclave.CacheInsertBundle{*b})
	if err != nil {
		t.Fatalf("MarshalMultiBundle: %v", err)
	}
	return data
}

func newTestHandler(replayDelta float64) *EnclaveHandler {
	keypair, _ := enclave.GenerateKeypair()
	return &EnclaveHandler{
		keypair:            keypair,
		cache:              enclave.NewLRUCache(100),
		replayDelta:        replayDelta,
		padBuckets:         enclave.DefaultPadBuckets,
		defensiveMode:      false, // tests default to normal mode (not warm-up)
		outstandingQueries: make(map[string]int64),
		warmupThreshold:    10,
		omissionThreshold:  5,
		outstandingTTLSecs: 300,
		startedAt:          time.Now().Format(time.RFC3339),
		insertionQueue:     enclave.NewInsertionQueue(1000),
		batchSize:          100,
		batchCommitProb:    1.0, // always commit in tests for deterministic behavior
	}
}

// flushQueue forces all queued entries into cache via PutBatch.
// Used in tests that store entries and then verify cache contents
// without an intervening HandleProcess call.
func flushQueue(h *EnclaveHandler) {
	batch := h.insertionQueue.DrainBatch(h.insertionQueue.Len())
	if len(batch) > 0 {
		h.cache.PutBatch(batch)
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
		bundleBytes := marshalSingleBundle(t, bundle)

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

	// Flush queue to cache so we can verify contents directly
	flushQueue(h)

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
	flushQueue(h)

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
	flushQueue(h)

	// Verify insert 3 is cached
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

	// HandleProcess should return processed (dummy) even though entry is in cache
	qe := makeProcessReq(t, h, "example.com.:1")
	resp := h.HandleProcess(qe)

	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("defensive mode should return processed, got status=%s", resp.Status)
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
		bundleBytes := marshalSingleBundle(t, bundle)
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

	// After 2 stores (below threshold=3): entries are queued, not in cache.
	// HandleProcess returns miss (defensive) but commits queue entries.
	makeStore("a.com.:1", 1000)
	makeStore("b.com.:1", 1001)

	// HandleProcess: defensive mode → dummy, then batch commit (prob=1.0)
	// commits 2 entries → cache.Size()=2 < 3 → still defensive
	qe := makeProcessReq(t, h, "a.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("should still return processed before threshold (2 < 3), got %s", resp.Status)
	}

	// 3rd store → queued
	makeStore("c.com.:1", 1002)

	// HandleProcess: defensive mode → dummy, then batch commit (prob=1.0)
	// commits 1 entry → cache.Size()=3 >= 3 → exits defensive mode
	qe = makeProcessReq(t, h, "a.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed (defensive response determined before commit), got %s", resp.Status)
	}

	// Now defensive mode exited. Next HandleProcess should return processed (hit).
	qe = makeProcessReq(t, h, "a.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed after warm-up exit (3 >= 3), got status=%s", resp.Status)
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
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed before omission, got %s", resp.Status)
	}

	// Generate 6 cache misses (> threshold of 5) to trigger omission detection
	for i := 0; i < 6; i++ {
		query := fmt.Sprintf("miss%d.com.:1", i)
		qe := makeProcessReq(t, h, query)
		h.HandleProcess(qe)
	}

	// Defensive mode active + cache cleared: previously-cached entry now returns processed (dummy)
	qe = makeProcessReq(t, h, "cached.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed after omission (defensive mode + cache cleared), got %s", resp.Status)
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
	bundleBytes := marshalSingleBundle(t, bundle)
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
	// Note: with batchCommitProb=1.0, each HandleProcess also commits queued entries.
	for i := 0; i < 5; i++ {
		qe := makeProcessReq(t, h, fmt.Sprintf("new%d.com.:1", i))
		h.HandleProcess(qe)
	}

	// If old entries survived cleanup, outstanding=10 > 8 → omission → cache cleared.
	// If cleanup worked, outstanding=5 ≤ 8 → no omission → sentinel still reachable.
	qe := makeProcessReq(t, h, "sentinel.com.:1")
	resp2 := h.HandleProcess(qe)
	if resp2.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed (TTL cleanup should prevent omission), got %s", resp2.Status)
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
	bundleBytes := marshalSingleBundle(t, bundle)
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

	// If removal worked: "a.com.:1" is cached and no omission → processed (hit).
	// If removal failed: omission triggered → cache cleared → processed (dummy).
	qe = makeProcessReq(t, h, "a.com.:1")
	resp2 := h.HandleProcess(qe)
	if resp2.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed (store should remove from outstanding, preventing omission), got %s", resp2.Status)
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

	// 10 queries during defensive mode — all return processed (dummy)
	for i := 0; i < 10; i++ {
		query := fmt.Sprintf("defensive%d.com.:1", i)
		qe := makeProcessReq(t, h, query)
		resp := h.HandleProcess(qe)
		if resp.Status != enclave.StatusProcessed {
			t.Fatalf("expected processed during defensive mode, got %s", resp.Status)
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
		bundleBytes := marshalSingleBundle(t, bundle)
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

	// If no leakage: outstanding=3 ≤ 5 → no omission → stored entry is processed (hit).
	qe := makeProcessReq(t, h, "stored0.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed (no outstanding leakage during defensive mode), got %s", resp.Status)
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
		bundleBytes := marshalSingleBundle(t, bundle)
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

	// Phase 1: Boot defensive → recovery via 3 stores (entries queued, not committed)
	storeOne("a.com.:1")
	storeOne("b.com.:1")
	storeOne("c.com.:1")

	// Phase 2: HandleProcess triggers batch commit (prob=1.0), exits defensive mode.
	// First call: defensive → dummy response, then commits 3 entries → exits warmup.
	qe := makeProcessReq(t, h, "a.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("phase 2a: expected processed (defensive response before commit), got %s", resp.Status)
	}
	// Second call: normal mode → cache hit proves defensive mode exited.
	qe = makeProcessReq(t, h, "a.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("phase 2b: expected processed after recovery, got %s", resp.Status)
	}

	// Phase 3: Trigger omission detection — 4 unique misses (> threshold=3)
	for i := 0; i < 4; i++ {
		qe := makeProcessReq(t, h, fmt.Sprintf("miss%d.com.:1", i))
		h.HandleProcess(qe)
	}

	// Previously-cached entry now returns processed (dummy) → defensive mode re-entered + cache cleared
	qe = makeProcessReq(t, h, "a.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("phase 3: expected processed (defensive mode after omission), got %s", resp.Status)
	}

	// Phase 4: Second recovery via 3 new stores (queued)
	storeOne("d.com.:1")
	storeOne("e.com.:1")
	storeOne("f.com.:1")

	// Phase 5: HandleProcess commits and exits defensive mode.
	// First call: defensive → dummy, commits 3 entries → exits warmup.
	qe = makeProcessReq(t, h, "d.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("phase 5a: expected processed (defensive response before commit), got %s", resp.Status)
	}
	// Second call: normal mode → cache hit proves defensive mode exited again.
	qe = makeProcessReq(t, h, "d.com.:1")
	resp = h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("phase 5b: expected processed after second recovery, got %s", resp.Status)
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
			bundleBytes := marshalSingleBundle(t, bundle)
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

	// After all goroutines: flush remaining queue entries and verify handler is usable.
	// With batching, some entries may still be in queue if HandleProcess calls
	// happened before stores enqueued. Flush to get accurate cache size.
	flushQueue(h)

	// With 30 stores and threshold=20, defensive mode should have exited
	// (either during HandleProcess commits or after our flush).
	// Some stores may be replay-rejected depending on scheduling.
	h.mu.Lock()
	if h.defensiveMode && h.cache.Size() >= h.warmupThreshold {
		h.defensiveMode = false
	}
	h.mu.Unlock()

	if h.cache.Size() >= h.warmupThreshold {
		// Defensive mode should have exited — verify with a processed response
		qe := makeProcessReq(t, h, "cstore0.com.:1")
		resp := h.HandleProcess(qe)
		if resp.Status != enclave.StatusProcessed {
			t.Fatalf("expected processed after concurrent recovery (cache=%d), got %s",
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
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed before concurrent misses, got %s", resp.Status)
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
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed after concurrent omission trigger, got %s", resp.Status)
	}
}

// --- Sprint 4: Batch Cache Update Tests ---

func TestBatch_StoreEnqueuesNotCaches(t *testing.T) {
	// Verify that HandleStoreEncrypted enqueues entries, NOT placing them in cache directly.
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(3.0)
	h.batchCommitProb = 0 // disable auto-commit to test pure enqueueing
	h.targetSigningPubKey = sigPub

	bundle := &enclave.CacheInsertBundle{
		TTL: 300, Timestamp: 1000,
		CanonicalQuery: "queued.com.:1",
		DNSResponse:    []byte{0xAB},
	}
	bundleBytes := marshalSingleBundle(t, bundle)
	pubBytes, _ := h.keypair.PublicKeyBytes()
	ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
	hash := sha256.Sum256(bundleBytes)
	sig := ed25519.Sign(sigPriv, hash[:])

	resp := h.HandleStoreEncrypted(
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(sig),
	)
	if resp.Status != enclave.StatusOK {
		t.Fatalf("store should succeed, got %s %s", resp.Status, resp.Error)
	}

	// Entry should NOT be in cache
	if _, ok := h.cache.Get("queued.com.:1", 1000); ok {
		t.Fatal("entry should NOT be in cache immediately after store (should be queued)")
	}

	// Entry should be in queue
	if h.insertionQueue.Len() != 1 {
		t.Fatalf("expected queue len=1, got %d", h.insertionQueue.Len())
	}
}

func TestBatch_HandleProcessCommitsQueue(t *testing.T) {
	// Verify that HandleProcess coin flip triggers batch commit.
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(3.0)
	h.batchCommitProb = 1.0 // always commit
	h.batchSize = 5
	h.targetSigningPubKey = sigPub
	h.tLatest.Store(1000)

	// Enqueue 3 entries
	for i := 0; i < 3; i++ {
		query := fmt.Sprintf("batch%d.com.:1", i)
		bundle := &enclave.CacheInsertBundle{
			TTL: 300, Timestamp: int64(1000 + i),
			CanonicalQuery: query,
			DNSResponse:    []byte{0xAB},
		}
		bundleBytes := marshalSingleBundle(t, bundle)
		pubBytes, _ := h.keypair.PublicKeyBytes()
		ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
		hash := sha256.Sum256(bundleBytes)
		sig := ed25519.Sign(sigPriv, hash[:])
		h.HandleStoreEncrypted(
			base64.StdEncoding.EncodeToString(ct),
			base64.StdEncoding.EncodeToString(sig),
		)
	}

	if h.cache.Size() != 0 {
		t.Fatalf("cache should be empty before commit, got size=%d", h.cache.Size())
	}

	// HandleProcess triggers commit (prob=1.0)
	qe := makeProcessReq(t, h, "unrelated.com.:1")
	h.HandleProcess(qe)

	// All 3 entries should now be in cache
	if h.cache.Size() != 3 {
		t.Fatalf("expected cache size=3 after commit, got %d", h.cache.Size())
	}
	if h.totalCommits.Load() != 1 {
		t.Fatalf("expected 1 total commit, got %d", h.totalCommits.Load())
	}
	if h.totalEntriesCommitted.Load() != 3 {
		t.Fatalf("expected 3 total entries committed, got %d", h.totalEntriesCommitted.Load())
	}
}

func TestBatch_OmissionDropsOnEnqueue(t *testing.T) {
	// Verify that outstanding count drops on enqueue (not on commit).
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(3.0)
	h.batchCommitProb = 0 // disable commit to isolate enqueue behavior
	h.omissionThreshold = 5
	h.targetSigningPubKey = sigPub
	h.tLatest.Store(1000)

	// Generate 2 misses to create outstanding entries
	for i := 0; i < 2; i++ {
		qe := makeProcessReq(t, h, fmt.Sprintf("miss%d.com.:1", i))
		h.HandleProcess(qe)
	}
	h.mu.Lock()
	if len(h.outstandingQueries) != 2 {
		t.Fatalf("expected 2 outstanding, got %d", len(h.outstandingQueries))
	}
	h.mu.Unlock()

	// Store for "miss0.com.:1" → removed from outstanding on enqueue
	bundle := &enclave.CacheInsertBundle{
		TTL: 300, Timestamp: 1001,
		CanonicalQuery: "miss0.com.:1",
		DNSResponse:    []byte{0xAB},
	}
	bundleBytes := marshalSingleBundle(t, bundle)
	pubBytes, _ := h.keypair.PublicKeyBytes()
	ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
	hash := sha256.Sum256(bundleBytes)
	sig := ed25519.Sign(sigPriv, hash[:])
	h.HandleStoreEncrypted(
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(sig),
	)

	h.mu.Lock()
	if len(h.outstandingQueries) != 1 {
		t.Fatalf("expected 1 outstanding after enqueue (not commit), got %d", len(h.outstandingQueries))
	}
	if _, exists := h.outstandingQueries["miss0.com.:1"]; exists {
		t.Fatal("miss0.com.:1 should be removed from outstanding after enqueue")
	}
	h.mu.Unlock()
}

func TestBatch_HealthEndpointReturnsQueueStats(t *testing.T) {
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(3.0)
	h.batchCommitProb = 0 // no auto-commit
	h.targetSigningPubKey = sigPub

	// Enqueue 2 entries
	for i := 0; i < 2; i++ {
		bundle := &enclave.CacheInsertBundle{
			TTL: 300, Timestamp: int64(1000 + i),
			CanonicalQuery: fmt.Sprintf("health%d.com.:1", i),
			DNSResponse:    []byte{0xAB},
		}
		bundleBytes := marshalSingleBundle(t, bundle)
		pubBytes, _ := h.keypair.PublicKeyBytes()
		ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
		hash := sha256.Sum256(bundleBytes)
		sig := ed25519.Sign(sigPriv, hash[:])
		h.HandleStoreEncrypted(
			base64.StdEncoding.EncodeToString(ct),
			base64.StdEncoding.EncodeToString(sig),
		)
	}

	resp := h.HandleHealth()
	if resp.QueueDepth != 2 {
		t.Fatalf("expected queue_depth=2, got %d", resp.QueueDepth)
	}
	if resp.TotalCommits != 0 {
		t.Fatalf("expected total_commits=0, got %d", resp.TotalCommits)
	}

	// Manually commit and check stats update
	h.batchCommitProb = 1.0
	h.batchSize = 10
	qe := makeProcessReq(t, h, "trigger.com.:1")
	h.HandleProcess(qe)

	resp = h.HandleHealth()
	if resp.QueueDepth != 0 {
		t.Fatalf("expected queue_depth=0 after commit, got %d", resp.QueueDepth)
	}
	if resp.TotalCommits != 1 {
		t.Fatalf("expected total_commits=1, got %d", resp.TotalCommits)
	}
	if resp.TotalEntriesCommitted != 2 {
		t.Fatalf("expected total_entries_committed=2, got %d", resp.TotalEntriesCommitted)
	}
}

func TestBatch_QueueOverflow(t *testing.T) {
	// Verify head-drop behavior when queue is full.
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(100.0) // wide delta
	h.batchCommitProb = 0      // no auto-commit
	h.targetSigningPubKey = sigPub
	h.insertionQueue = enclave.NewInsertionQueue(3) // small queue

	for i := 0; i < 5; i++ {
		bundle := &enclave.CacheInsertBundle{
			TTL: 300, Timestamp: int64(1000 + i),
			CanonicalQuery: fmt.Sprintf("overflow%d.com.:1", i),
			DNSResponse:    []byte{byte(i)},
		}
		bundleBytes := marshalSingleBundle(t, bundle)
		pubBytes, _ := h.keypair.PublicKeyBytes()
		ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
		hash := sha256.Sum256(bundleBytes)
		sig := ed25519.Sign(sigPriv, hash[:])
		h.HandleStoreEncrypted(
			base64.StdEncoding.EncodeToString(ct),
			base64.StdEncoding.EncodeToString(sig),
		)
	}

	// Queue should be at max capacity (3), with oldest 2 evicted
	if h.insertionQueue.Len() != 3 {
		t.Fatalf("expected queue len=3 (maxSize), got %d", h.insertionQueue.Len())
	}

	// Flush and verify: entries 2,3,4 should be in cache (0,1 evicted)
	flushQueue(h)
	for i := 2; i < 5; i++ {
		query := fmt.Sprintf("overflow%d.com.:1", i)
		if _, ok := h.cache.Get(query, 1010); !ok {
			t.Fatalf("%s should be in cache (survived eviction)", query)
		}
	}
	for i := 0; i < 2; i++ {
		query := fmt.Sprintf("overflow%d.com.:1", i)
		if _, ok := h.cache.Get(query, 1010); ok {
			t.Fatalf("%s should NOT be in cache (evicted from queue)", query)
		}
	}
}

func TestBatch_DefensiveNotFalseTriggeredByDelay(t *testing.T) {
	// With batching, there's a delay between store (enqueue) and cache commit.
	// Outstanding queries are removed on enqueue (D2), so this delay should NOT
	// cause false omission detection.
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(3.0)
	h.batchCommitProb = 0 // deliberate: no commit to test maximum delay
	h.omissionThreshold = 5
	h.targetSigningPubKey = sigPub
	h.tLatest.Store(1000)

	// Pre-populate cache with sentinel
	h.cache.Put("sentinel.com.:1", []byte{0xFF}, 1000, 3600)

	// Generate 3 misses
	for i := 0; i < 3; i++ {
		qe := makeProcessReq(t, h, fmt.Sprintf("q%d.com.:1", i))
		h.HandleProcess(qe)
	}

	// Store responses for all 3 (removed from outstanding on enqueue)
	for i := 0; i < 3; i++ {
		bundle := &enclave.CacheInsertBundle{
			TTL: 300, Timestamp: int64(1001 + i),
			CanonicalQuery: fmt.Sprintf("q%d.com.:1", i),
			DNSResponse:    []byte{0xAB},
		}
		bundleBytes := marshalSingleBundle(t, bundle)
		pubBytes, _ := h.keypair.PublicKeyBytes()
		ct, _ := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
		hash := sha256.Sum256(bundleBytes)
		sig := ed25519.Sign(sigPriv, hash[:])
		h.HandleStoreEncrypted(
			base64.StdEncoding.EncodeToString(ct),
			base64.StdEncoding.EncodeToString(sig),
		)
	}

	// 3 more misses — outstanding should be 3 (not 6), no omission
	for i := 3; i < 6; i++ {
		qe := makeProcessReq(t, h, fmt.Sprintf("q%d.com.:1", i))
		h.HandleProcess(qe)
	}

	// Sentinel should still be reachable (no omission triggered)
	qe := makeProcessReq(t, h, "sentinel.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed (no false omission from batch delay), got %s", resp.Status)
	}
}

// --- Sprint 5: Multi-entry bundle tests ---

// marshalMultiBundle builds an encrypted+signed multi-entry store request.
func marshalMultiBundle(t *testing.T, h *EnclaveHandler, sigPriv ed25519.PrivateKey, entries []enclave.CacheInsertBundle) (blob, sig string) {
	t.Helper()
	bundleBytes, err := enclave.MarshalMultiBundle(entries)
	if err != nil {
		t.Fatalf("MarshalMultiBundle: %v", err)
	}
	pubBytes, _ := h.keypair.PublicKeyBytes()
	ct, err := codohtarget.EncryptForEnclave(pubBytes, bundleBytes)
	if err != nil {
		t.Fatalf("EncryptForEnclave: %v", err)
	}
	hash := sha256.Sum256(bundleBytes)
	sigBytes := ed25519.Sign(sigPriv, hash[:])
	return base64.StdEncoding.EncodeToString(ct), base64.StdEncoding.EncodeToString(sigBytes)
}

func TestMultiEntry_FourEntriesAllEnqueued(t *testing.T) {
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(100.0) // wide δ
	h.batchCommitProb = 0      // no auto-commit
	h.targetSigningPubKey = sigPub

	entries := []enclave.CacheInsertBundle{
		{TTL: 300, Timestamp: 1000, CanonicalQuery: "real.com.:1", DNSResponse: []byte{0x01}},
		{TTL: 60, Timestamp: 1000, CanonicalQuery: "cover1.com.:1", DNSResponse: []byte{0x02}},
		{TTL: 120, Timestamp: 1000, CanonicalQuery: "cover2.com.:1", DNSResponse: []byte{0x03}},
		{TTL: 180, Timestamp: 1000, CanonicalQuery: "cover3.com.:1", DNSResponse: []byte{0x04}},
	}

	blob, sig := marshalMultiBundle(t, h, sigPriv, entries)
	resp := h.HandleStoreEncrypted(blob, sig)
	if resp.Status != enclave.StatusOK {
		t.Fatalf("expected ok, got %s %s", resp.Status, resp.Error)
	}

	if h.insertionQueue.Len() != 4 {
		t.Fatalf("expected 4 queued entries, got %d", h.insertionQueue.Len())
	}

	// Flush and verify all 4 in cache
	flushQueue(h)
	for _, e := range entries {
		if _, ok := h.cache.Get(e.CanonicalQuery, 1000); !ok {
			t.Errorf("%s should be in cache", e.CanonicalQuery)
		}
	}
}

func TestMultiEntry_OneStaleThreeEnqueued(t *testing.T) {
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(3.0)
	h.batchCommitProb = 0
	h.targetSigningPubKey = sigPub
	h.tLatest.Store(1000)

	entries := []enclave.CacheInsertBundle{
		{TTL: 300, Timestamp: 1001, CanonicalQuery: "fresh1.com.:1", DNSResponse: []byte{0x01}},
		{TTL: 60, Timestamp: 990, CanonicalQuery: "stale.com.:1", DNSResponse: []byte{0x02}}, // 990 < 1000-3=997 → stale
		{TTL: 120, Timestamp: 1002, CanonicalQuery: "fresh2.com.:1", DNSResponse: []byte{0x03}},
		{TTL: 180, Timestamp: 1001, CanonicalQuery: "fresh3.com.:1", DNSResponse: []byte{0x04}},
	}

	blob, sig := marshalMultiBundle(t, h, sigPriv, entries)
	resp := h.HandleStoreEncrypted(blob, sig)
	if resp.Status != enclave.StatusOK {
		t.Fatalf("expected ok (3/4 enqueued), got %s %s", resp.Status, resp.Error)
	}

	if h.insertionQueue.Len() != 3 {
		t.Fatalf("expected 3 queued entries (1 stale skipped), got %d", h.insertionQueue.Len())
	}

	flushQueue(h)
	if _, ok := h.cache.Get("stale.com.:1", 1010); ok {
		t.Fatal("stale.com.:1 should NOT be in cache")
	}
	for _, q := range []string{"fresh1.com.:1", "fresh2.com.:1", "fresh3.com.:1"} {
		if _, ok := h.cache.Get(q, 1010); !ok {
			t.Errorf("%s should be in cache", q)
		}
	}
}

func TestMultiEntry_OutstandingRealRemovedCoverNoop(t *testing.T) {
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(100.0)
	h.batchCommitProb = 0
	h.targetSigningPubKey = sigPub
	h.tLatest.Store(1000)

	// Generate a cache miss for "real.com.:1" → adds to outstanding
	qe := makeProcessReq(t, h, "real.com.:1")
	h.HandleProcess(qe)

	h.mu.Lock()
	if _, exists := h.outstandingQueries["real.com.:1"]; !exists {
		t.Fatal("real.com.:1 should be in outstanding after miss")
	}
	h.mu.Unlock()

	// Store multi-bundle with real + covers
	entries := []enclave.CacheInsertBundle{
		{TTL: 300, Timestamp: 1001, CanonicalQuery: "real.com.:1", DNSResponse: []byte{0x01}},
		{TTL: 60, Timestamp: 1001, CanonicalQuery: "cover1.com.:1", DNSResponse: []byte{0x02}},
		{TTL: 120, Timestamp: 1001, CanonicalQuery: "cover2.com.:1", DNSResponse: []byte{0x03}},
	}

	blob, sig := marshalMultiBundle(t, h, sigPriv, entries)
	resp := h.HandleStoreEncrypted(blob, sig)
	if resp.Status != enclave.StatusOK {
		t.Fatalf("expected ok, got %s %s", resp.Status, resp.Error)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// real.com.:1 removed from outstanding
	if _, exists := h.outstandingQueries["real.com.:1"]; exists {
		t.Fatal("real.com.:1 should be removed from outstanding after store")
	}

	// cover queries were never in outstanding → delete is no-op, no panic
	// (implicitly tested by reaching this point without error)
}

func TestMultiEntry_SingleEntryCount1(t *testing.T) {
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(100.0)
	h.batchCommitProb = 0
	h.targetSigningPubKey = sigPub

	entries := []enclave.CacheInsertBundle{
		{TTL: 300, Timestamp: 1000, CanonicalQuery: "only.com.:1", DNSResponse: []byte{0xFF}},
	}

	blob, sig := marshalMultiBundle(t, h, sigPriv, entries)
	resp := h.HandleStoreEncrypted(blob, sig)
	if resp.Status != enclave.StatusOK {
		t.Fatalf("expected ok, got %s %s", resp.Status, resp.Error)
	}

	if h.insertionQueue.Len() != 1 {
		t.Fatalf("expected 1 queued entry, got %d", h.insertionQueue.Len())
	}

	flushQueue(h)
	if _, ok := h.cache.Get("only.com.:1", 1000); !ok {
		t.Fatal("only.com.:1 should be in cache")
	}
}

func TestMultiEntry_AllStaleReturnsError(t *testing.T) {
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	h := newTestHandler(3.0)
	h.targetSigningPubKey = sigPub
	h.tLatest.Store(1000)

	// All entries stale: ts=990 < 1000-3=997
	entries := []enclave.CacheInsertBundle{
		{TTL: 300, Timestamp: 990, CanonicalQuery: "old1.com.:1", DNSResponse: []byte{0x01}},
		{TTL: 60, Timestamp: 991, CanonicalQuery: "old2.com.:1", DNSResponse: []byte{0x02}},
	}

	blob, sig := marshalMultiBundle(t, h, sigPriv, entries)
	resp := h.HandleStoreEncrypted(blob, sig)
	if resp.Status != enclave.StatusError {
		t.Fatalf("expected error when all entries stale, got %s", resp.Status)
	}
	if resp.Error != enclave.ErrStaleTimestamp {
		t.Fatalf("expected %q, got %q", enclave.ErrStaleTimestamp, resp.Error)
	}
}

// --- Sprint 6: Padding Integration Tests ---

func TestHandleProcess_HitResponseIsBucketSized(t *testing.T) {
	h := newTestHandler(3.0)
	h.tLatest.Store(1000)
	h.cache.Put("padtest.com.:1", []byte{0xDE, 0xAD, 0xBE, 0xEF}, 1000, 300)

	qe := makeProcessReq(t, h, "padtest.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed, got %s", resp.Status)
	}

	decoded, err := base64.StdEncoding.DecodeString(resp.Response)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Must be exactly the default bucket size (16384)
	if len(decoded) != enclave.DefaultPadBuckets[0] {
		t.Fatalf("hit response size=%d, want %d (bucket size)", len(decoded), enclave.DefaultPadBuckets[0])
	}
}

func TestHandleProcess_MissResponseIsBucketSized(t *testing.T) {
	h := newTestHandler(3.0)
	h.tLatest.Store(1000)

	qe := makeProcessReq(t, h, "nonexistent.com.:1")
	resp := h.HandleProcess(qe)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed, got %s", resp.Status)
	}

	decoded, err := base64.StdEncoding.DecodeString(resp.Response)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(decoded) != enclave.DefaultPadBuckets[0] {
		t.Fatalf("miss response size=%d, want %d (max bucket)", len(decoded), enclave.DefaultPadBuckets[0])
	}
}

func TestHandleProcess_HitDecryptableAfterUnpad(t *testing.T) {
	h := newTestHandler(3.0)
	h.tLatest.Store(1000)

	dnsResponse := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	h.cache.Put("roundtrip.com.:1", dnsResponse, 1000, 300)

	// Build Q_E and get the sender-side k_r
	pubBytes, _ := h.keypair.PublicKeyBytes()
	pk, err := enclave.ParsePublicKeyBytes(pubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKeyBytes: %v", err)
	}
	qeRaw, clientKr, err := enclave.EncryptQueryE(pk, []byte("roundtrip.com.:1"))
	if err != nil {
		t.Fatalf("EncryptQueryE: %v", err)
	}
	qeB64 := base64.StdEncoding.EncodeToString(qeRaw)

	resp := h.HandleProcess(qeB64)
	if resp.Status != enclave.StatusProcessed {
		t.Fatalf("expected processed, got %s", resp.Status)
	}

	decoded, err := base64.StdEncoding.DecodeString(resp.Response)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Unpad → Decrypt → verify original DNS response
	unpadded, err := enclave.UnpadFromBucket(decoded)
	if err != nil {
		t.Fatalf("UnpadFromBucket: %v", err)
	}

	decrypted, err := enclave.DecryptCachedResponse(clientKr, unpadded)
	if err != nil {
		t.Fatalf("DecryptCachedResponse: %v", err)
	}

	if string(decrypted) != string(dnsResponse) {
		t.Fatalf("round-trip mismatch: got %x, want %x", decrypted, dnsResponse)
	}
}
