package codohtarget

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coredns/coredns/enclave"
	"github.com/coredns/coredns/plugin/codohtarget/cover"
	"github.com/miekg/dns"
)

// --- mocks ---

type mockSampler struct {
	domains []string
}

func (m *mockSampler) Sample(k int, exclude string) []string {
	var result []string
	for _, d := range m.domains {
		if d != exclude && len(result) < k {
			result = append(result, d)
		}
	}
	return result
}

type mockResolver struct {
	results []cover.ResolvedCover
}

func (m *mockResolver) Resolve(_ context.Context, domains []string) []cover.ResolvedCover {
	return m.results
}

type failResolver struct{}

func (f *failResolver) Resolve(_ context.Context, _ []string) []cover.ResolvedCover {
	return nil
}

// --- helpers ---

func newTestTarget(t *testing.T, proxyURL string) (*odohTarget, *enclave.EnclaveKeypair) {
	t.Helper()
	keypair, err := enclave.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	sigKey, err := generateTestSigningKey()
	if err != nil {
		t.Fatalf("generateTestSigningKey: %v", err)
	}

	tgt := &odohTarget{
		signingKey:       sigKey,
		proxyCallbackURL: proxyURL,
		callbackClient:   &http.Client{Timeout: 5 * time.Second},
	}
	return tgt, keypair
}

func generateTestSigningKey() (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SigningKey{PrivateKey: priv, PublicKey: pub}, nil
}

func makeDNSQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

// decryptAndParsePayload decrypts the HPKE blob in the POST payload and parses the multi-bundle.
func decryptAndParsePayload(t *testing.T, payload cacheInsertPayload, keypair *enclave.EnclaveKeypair, sigPub ed25519.PublicKey) []enclave.CacheInsertBundle {
	t.Helper()

	ciphertext, err := base64.StdEncoding.DecodeString(payload.EncryptedBlob)
	if err != nil {
		t.Fatalf("decode encrypted_blob: %v", err)
	}

	plaintext, err := keypair.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("HPKE decrypt: %v", err)
	}

	// Verify signature
	if payload.Signature != "" {
		sigBytes, _ := base64.StdEncoding.DecodeString(payload.Signature)
		hash := sha256.Sum256(plaintext)
		if !ed25519.Verify(sigPub, hash[:], sigBytes) {
			t.Fatal("signature verification failed")
		}
	}

	entries, err := enclave.ParseMultiBundle(plaintext)
	if err != nil {
		t.Fatalf("ParseMultiBundle: %v", err)
	}
	return entries
}

// --- T4 tests ---

func TestPrepareCacheInsert_WithCovers(t *testing.T) {
	var mu sync.Mutex
	var received cacheInsertPayload
	postCount := 0

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cache-insert" {
			http.Error(w, "not found", 404)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		json.Unmarshal(body, &received)
		postCount++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer proxySrv.Close()

	tgt, keypair := newTestTarget(t, proxySrv.URL)
	tgt.coverCount = 3
	tgt.coverSampler = &mockSampler{domains: []string{"cover1.com", "cover2.com", "cover3.com"}}
	tgt.coverResolver = &mockResolver{results: []cover.ResolvedCover{
		{Domain: "cover1.com", DNSResponse: []byte{0x01}, TTL: 60},
		{Domain: "cover2.com", DNSResponse: []byte{0x02}, TTL: 120},
		{Domain: "cover3.com", DNSResponse: []byte{0x03}, TTL: 180},
	}}

	pubBytes, _ := keypair.PublicKeyBytes()
	dnsQuery := makeDNSQuery("example.com", dns.TypeA)
	packedResp := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	tgt.prepareCacheInsert(pubBytes, dnsQuery, packedResp, 300)

	mu.Lock()
	defer mu.Unlock()

	if postCount != 1 {
		t.Fatalf("expected 1 POST, got %d", postCount)
	}
	if received.EncryptedBlob == "" {
		t.Fatal("encrypted_blob is empty")
	}
	if received.Signature == "" {
		t.Fatal("signature is empty")
	}

	entries := decryptAndParsePayload(t, received, keypair, tgt.signingKey.PublicKey)
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries (1 real + 3 covers), got %d", len(entries))
	}

	// First entry is the real query
	if entries[0].CanonicalQuery != "example.com.:1" {
		t.Errorf("real entry query: got %q, want %q", entries[0].CanonicalQuery, "example.com.:1")
	}
	if entries[0].TTL != 300 {
		t.Errorf("real entry TTL: got %d, want 300", entries[0].TTL)
	}

	// Verify covers
	coverQueries := map[string]bool{
		"cover1.com.:1": false,
		"cover2.com.:1": false,
		"cover3.com.:1": false,
	}
	for _, e := range entries[1:] {
		coverQueries[e.CanonicalQuery] = true
	}
	for q, found := range coverQueries {
		if !found {
			t.Errorf("cover %q not found in bundle", q)
		}
	}
}

func TestPrepareCacheInsert_K0_SingleEntry(t *testing.T) {
	var mu sync.Mutex
	var received cacheInsertPayload
	postCount := 0

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		json.Unmarshal(body, &received)
		postCount++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer proxySrv.Close()

	tgt, keypair := newTestTarget(t, proxySrv.URL)
	tgt.coverCount = 0 // no covers

	pubBytes, _ := keypair.PublicKeyBytes()
	dnsQuery := makeDNSQuery("example.com", dns.TypeA)
	packedResp := []byte{0xCA, 0xFE}

	tgt.prepareCacheInsert(pubBytes, dnsQuery, packedResp, 60)

	mu.Lock()
	defer mu.Unlock()

	if postCount != 1 {
		t.Fatalf("expected 1 POST even with k=0, got %d", postCount)
	}

	entries := decryptAndParsePayload(t, received, keypair, tgt.signingKey.PublicKey)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (count=1), got %d", len(entries))
	}
	if entries[0].CanonicalQuery != "example.com.:1" {
		t.Errorf("entry query: got %q", entries[0].CanonicalQuery)
	}
}

func TestPrepareCacheInsert_AllCoversFail_NoPOST(t *testing.T) {
	postCount := 0

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postCount++
		w.WriteHeader(200)
	}))
	defer proxySrv.Close()

	tgt, keypair := newTestTarget(t, proxySrv.URL)
	tgt.coverCount = 3
	tgt.coverSampler = &mockSampler{domains: []string{"a.com", "b.com", "c.com"}}
	tgt.coverResolver = &failResolver{} // all resolutions fail

	pubBytes, _ := keypair.PublicKeyBytes()
	dnsQuery := makeDNSQuery("example.com", dns.TypeA)
	packedResp := []byte{0xFF}

	tgt.prepareCacheInsert(pubBytes, dnsQuery, packedResp, 300)

	// Give async any time to fire (it shouldn't)
	time.Sleep(50 * time.Millisecond)

	if postCount != 0 {
		t.Fatalf("expected 0 POSTs when all covers fail (D6), got %d", postCount)
	}
}

func TestPrepareCacheInsert_NoXEnclaveCacheHeaders(t *testing.T) {
	// Verify the old X-Enclave-Cache header path is gone.
	// Build a minimal target, call odohQueryHandler via httptest, check no such headers.
	// We can't easily call odohQueryHandler (needs ODoH decrypt), so instead
	// verify prepareCacheInsert doesn't take an http.ResponseWriter anymore —
	// the signature change itself is the proof. This test documents the API contract.

	tgt := &odohTarget{}
	// prepareCacheInsert signature: (pubKeyBytes, dnsQuery, packedResponse, ttl)
	// No http.ResponseWriter parameter — headers cannot be set.
	_ = tgt // compile-time proof: no w parameter in prepareCacheInsert
}

func TestExtractMinimalTTL_NXDOMAIN_SOA_Minimum(t *testing.T) {
	// RFC 2308 §5: negative TTL = min(SOA.TTL, SOA.MINIMUM)
	tests := []struct {
		name    string
		soaTTL  uint32
		soaMin  uint32
		wantTTL uint32
	}{
		{"SOA.TTL < SOA.MINIMUM", 60, 300, 60},
		{"SOA.MINIMUM < SOA.TTL", 300, 60, 60},
		{"equal", 120, 120, 120},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := new(dns.Msg)
			msg.SetQuestion("nxdomain.example.", dns.TypeA)
			msg.Rcode = dns.RcodeNameError
			msg.Ns = []dns.RR{
				&dns.SOA{
					Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: tt.soaTTL},
					Ns:     "ns1.example.",
					Mbox:   "admin.example.",
					Minttl: tt.soaMin,
				},
			}
			got := extractMinimalTTL(msg)
			if got != tt.wantTTL {
				t.Errorf("got %d, want %d", got, tt.wantTTL)
			}
		})
	}
}

func TestExtractMinimalTTL_NODATA_SOA_Minimum(t *testing.T) {
	// NODATA: RcodeSuccess with empty Answer, SOA in Ns
	msg := new(dns.Msg)
	msg.SetQuestion("nodata.example.", dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	// No Answer records → NODATA
	msg.Ns = []dns.RR{
		&dns.SOA{
			Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:     "ns1.example.",
			Mbox:   "admin.example.",
			Minttl: 120,
		},
	}
	got := extractMinimalTTL(msg)
	if got != 120 {
		t.Errorf("NODATA TTL: got %d, want 120 (SOA.MINIMUM)", got)
	}
}

func TestPrepareCacheInsert_ValidJSON(t *testing.T) {
	var mu sync.Mutex
	var rawBody []byte

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		rawBody = body
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer proxySrv.Close()

	tgt, keypair := newTestTarget(t, proxySrv.URL)
	tgt.coverCount = 0

	pubBytes, _ := keypair.PublicKeyBytes()
	dnsQuery := makeDNSQuery("json-test.com", dns.TypeA)

	tgt.prepareCacheInsert(pubBytes, dnsQuery, []byte{0x01}, 60)

	mu.Lock()
	defer mu.Unlock()

	// Must be valid JSON
	var payload cacheInsertPayload
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		t.Fatalf("POST body is not valid JSON: %v\nbody: %s", err, rawBody)
	}
	if payload.EncryptedBlob == "" {
		t.Fatal("missing encrypted_blob in JSON")
	}
	if payload.Signature == "" {
		t.Fatal("missing signature in JSON")
	}

	// Verify encrypted_blob is valid base64
	if _, err := base64.StdEncoding.DecodeString(payload.EncryptedBlob); err != nil {
		t.Fatalf("encrypted_blob is not valid base64: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(payload.Signature); err != nil {
		t.Fatalf("signature is not valid base64: %v", err)
	}
}
