package enclave

import (
	"testing"
)

func TestLRUCache_LogicalTimeExpiry(t *testing.T) {
	cache := NewLRUCache(100)

	query := "example.com.:1"
	cache.Put(query, []byte("response"), 100, 60) // InsertedAt=100, TTL=60 → expires at 160

	// tLatest=150: 100+60=160, 160 < 150 is false → not expired
	if _, ok := cache.Get(query, 150); !ok {
		t.Error("expected entry to be valid at tLatest=150")
	}

	// tLatest=155: 160 < 155 is false → not expired
	if _, ok := cache.Get(query, 155); !ok {
		t.Error("expected entry to be valid at tLatest=155")
	}

	// tLatest=160: 160 < 160 is false → not expired (boundary: equal means still valid)
	if _, ok := cache.Get(query, 160); !ok {
		t.Error("expected entry to be valid at tLatest=160 (boundary)")
	}

	// tLatest=161: 160 < 161 is true → expired
	if _, ok := cache.Get(query, 161); ok {
		t.Error("expected entry to be expired at tLatest=161")
	}
}

func TestLRUCache_CleanExpired_LogicalTime(t *testing.T) {
	cache := NewLRUCache(100)

	cache.Put("a.com.:1", []byte("a"), 100, 60)  // expires at 160
	cache.Put("b.com.:1", []byte("b"), 100, 120) // expires at 220
	cache.Put("c.com.:1", []byte("c"), 200, 60)  // expires at 260

	// tLatest=161: only "a" is expired
	removed := cache.CleanExpired(161)
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if cache.Size() != 2 {
		t.Errorf("expected size 2, got %d", cache.Size())
	}

	// tLatest=221: "b" is now expired
	removed = cache.CleanExpired(221)
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if cache.Size() != 1 {
		t.Errorf("expected size 1, got %d", cache.Size())
	}

	// Remaining entry is c
	if _, ok := cache.Get("c.com.:1", 250); !ok {
		t.Error("expected c.com.:1 to still be valid")
	}
}

func TestLRUCache_PutUpdate_LogicalTime(t *testing.T) {
	cache := NewLRUCache(100)

	query := "example.com.:1"
	cache.Put(query, []byte("v1"), 100, 60) // expires at 160

	// Update with newer timestamp
	cache.Put(query, []byte("v2"), 200, 60) // now expires at 260

	// Old expiry shouldn't matter
	resp, ok := cache.Get(query, 200)
	if !ok {
		t.Fatal("expected to find updated entry")
	}
	if string(resp) != "v2" {
		t.Errorf("expected v2, got %s", resp)
	}

	// Should still be valid at 250
	if _, ok := cache.Get(query, 250); !ok {
		t.Error("expected updated entry valid at tLatest=250")
	}

	// Expired at 261
	if _, ok := cache.Get(query, 261); ok {
		t.Error("expected updated entry expired at tLatest=261")
	}
}

func TestLRUCache_GetWithZeroTLatest(t *testing.T) {
	cache := NewLRUCache(100)

	// Simulate bootstrap: tLatest=0, entry has real timestamp
	cache.Put("example.com.:1", []byte("resp"), 1700000000, 300)

	// tLatest=0: InsertedAt+TTL = 1700000300 < 0 is false → not expired
	resp, ok := cache.Get("example.com.:1", 0)
	if !ok {
		t.Error("expected entry to be valid with tLatest=0")
	}
	if string(resp) != "resp" {
		t.Errorf("unexpected response: %s", resp)
	}
}
