package enclave

import (
	"bytes"
	"testing"
	"time"
)

func TestCacheInsertBundle_RoundTrip(t *testing.T) {
	original := &CacheInsertBundle{
		TTL:            300,
		Timestamp:      time.Now().Unix(),
		CanonicalQuery: "example.com.:1",
		DNSResponse:    []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03},
	}

	data := MarshalCacheInsertBundle(original)
	parsed, err := ParseCacheInsertBundle(data)
	if err != nil {
		t.Fatalf("ParseCacheInsertBundle: %v", err)
	}

	if parsed.TTL != original.TTL {
		t.Errorf("TTL: got %d, want %d", parsed.TTL, original.TTL)
	}
	if parsed.Timestamp != original.Timestamp {
		t.Errorf("Timestamp: got %d, want %d", parsed.Timestamp, original.Timestamp)
	}
	if parsed.CanonicalQuery != original.CanonicalQuery {
		t.Errorf("CanonicalQuery: got %q, want %q", parsed.CanonicalQuery, original.CanonicalQuery)
	}
	if !bytes.Equal(parsed.DNSResponse, original.DNSResponse) {
		t.Errorf("DNSResponse: got %x, want %x", parsed.DNSResponse, original.DNSResponse)
	}
}

func TestCacheInsertBundle_EmptyQuery(t *testing.T) {
	original := &CacheInsertBundle{
		TTL:            60,
		Timestamp:      1000000,
		CanonicalQuery: "",
		DNSResponse:    []byte{0x01},
	}

	data := MarshalCacheInsertBundle(original)
	parsed, err := ParseCacheInsertBundle(data)
	if err != nil {
		t.Fatalf("ParseCacheInsertBundle: %v", err)
	}

	if parsed.CanonicalQuery != "" {
		t.Errorf("CanonicalQuery: got %q, want empty", parsed.CanonicalQuery)
	}
	if !bytes.Equal(parsed.DNSResponse, original.DNSResponse) {
		t.Errorf("DNSResponse mismatch")
	}
}

func TestCacheInsertBundle_TooShort(t *testing.T) {
	_, err := ParseCacheInsertBundle([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestCacheInsertBundle_QueryLenExceedsData(t *testing.T) {
	// 4 (ttl) + 8 (ts) + 2 (query_len=9999) = 14 bytes, but no query data
	data := MarshalCacheInsertBundle(&CacheInsertBundle{
		TTL:            1,
		Timestamp:      1,
		CanonicalQuery: "x",
		DNSResponse:    nil,
	})
	// Corrupt query_len to exceed buffer
	data[12] = 0xFF
	data[13] = 0xFF

	_, err := ParseCacheInsertBundle(data)
	if err == nil {
		t.Fatal("expected error for corrupt query_len")
	}
}