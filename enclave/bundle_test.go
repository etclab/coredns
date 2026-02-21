package enclave

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

func TestMultiBundle_RoundTrip(t *testing.T) {
	now := time.Now().Unix()
	entries := []CacheInsertBundle{
		{TTL: 300, Timestamp: now, CanonicalQuery: "example.com.:1", DNSResponse: []byte{0xDE, 0xAD}},
		{TTL: 60, Timestamp: now, CanonicalQuery: "cover1.com.:1", DNSResponse: []byte{0x01, 0x02, 0x03}},
		{TTL: 120, Timestamp: now, CanonicalQuery: "cover2.net.:1", DNSResponse: []byte{0xCA, 0xFE}},
		{TTL: 3600, Timestamp: now, CanonicalQuery: "cover3.org.:1", DNSResponse: []byte{0xBE, 0xEF, 0x00}},
	}

	data, err := MarshalMultiBundle(entries)
	if err != nil {
		t.Fatalf("MarshalMultiBundle: %v", err)
	}

	parsed, err := ParseMultiBundle(data)
	if err != nil {
		t.Fatalf("ParseMultiBundle: %v", err)
	}

	if len(parsed) != len(entries) {
		t.Fatalf("count: got %d, want %d", len(parsed), len(entries))
	}

	for i, want := range entries {
		got := parsed[i]
		if got.TTL != want.TTL {
			t.Errorf("entry %d TTL: got %d, want %d", i, got.TTL, want.TTL)
		}
		if got.Timestamp != want.Timestamp {
			t.Errorf("entry %d Timestamp: got %d, want %d", i, got.Timestamp, want.Timestamp)
		}
		if got.CanonicalQuery != want.CanonicalQuery {
			t.Errorf("entry %d CanonicalQuery: got %q, want %q", i, got.CanonicalQuery, want.CanonicalQuery)
		}
		if !bytes.Equal(got.DNSResponse, want.DNSResponse) {
			t.Errorf("entry %d DNSResponse: got %x, want %x", i, got.DNSResponse, want.DNSResponse)
		}
	}
}

func TestMultiBundle_SingleEntry(t *testing.T) {
	entries := []CacheInsertBundle{
		{TTL: 300, Timestamp: 1000000, CanonicalQuery: "single.com.:1", DNSResponse: []byte{0xFF}},
	}

	data, err := MarshalMultiBundle(entries)
	if err != nil {
		t.Fatalf("MarshalMultiBundle: %v", err)
	}

	parsed, err := ParseMultiBundle(data)
	if err != nil {
		t.Fatalf("ParseMultiBundle: %v", err)
	}

	if len(parsed) != 1 {
		t.Fatalf("count: got %d, want 1", len(parsed))
	}
	if parsed[0].CanonicalQuery != "single.com.:1" {
		t.Errorf("CanonicalQuery: got %q", parsed[0].CanonicalQuery)
	}
}

func TestMultiBundle_EmptyEntries(t *testing.T) {
	_, err := MarshalMultiBundle(nil)
	if err == nil {
		t.Fatal("expected error for nil entries")
	}
	_, err = MarshalMultiBundle([]CacheInsertBundle{})
	if err == nil {
		t.Fatal("expected error for empty entries")
	}
}

func TestMultiBundle_CountZero(t *testing.T) {
	// Manually craft a buffer with count=0
	data := []byte{0x00, 0x00}
	_, err := ParseMultiBundle(data)
	if err == nil {
		t.Fatal("expected error for count=0")
	}
}

func TestMultiBundle_Truncated(t *testing.T) {
	entries := []CacheInsertBundle{
		{TTL: 300, Timestamp: 1000, CanonicalQuery: "a.com.:1", DNSResponse: []byte{0x01, 0x02}},
	}
	data, _ := MarshalMultiBundle(entries)

	// Truncate at various points
	for _, cut := range []int{0, 1, 2, 3, 5, len(data) - 1} {
		_, err := ParseMultiBundle(data[:cut])
		if err == nil {
			t.Errorf("expected error for truncated data at %d bytes", cut)
		}
	}
}

func TestMultiBundle_FuzzNoPanic(t *testing.T) {
	for i := 0; i < 1000; i++ {
		buf := make([]byte, i%64)
		rand.Read(buf)
		ParseMultiBundle(buf) // must not panic
	}
}

func TestMultiBundle_SignatureCoversAll(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	now := time.Now().Unix()
	entries := []CacheInsertBundle{
		{TTL: 300, Timestamp: now, CanonicalQuery: "real.com.:1", DNSResponse: []byte{0xDE, 0xAD}},
		{TTL: 60, Timestamp: now, CanonicalQuery: "cover.com.:1", DNSResponse: []byte{0xBE, 0xEF}},
	}

	data, _ := MarshalMultiBundle(entries)

	hash := sha256.Sum256(data)
	sig := ed25519.Sign(priv, hash[:])

	if !ed25519.Verify(pub, hash[:], sig) {
		t.Fatal("signature should verify on original data")
	}

	// Tamper with second entry's TTL
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[len(tampered)-5] ^= 0xFF

	tamperedHash := sha256.Sum256(tampered)
	if ed25519.Verify(pub, tamperedHash[:], sig) {
		t.Fatal("signature should NOT verify after tampering")
	}
}
