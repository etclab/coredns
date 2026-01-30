package enclave

import (
	"testing"
	"time"
)

func TestORAMCache_BasicOperations(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    1024,
		BucketSize:   4,
		ConstantTime: false,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		t.Fatalf("NewORAMCache failed: %v", err)
	}

	// Test Put and Get
	query := "example.com."
	response := []byte("dns response data")
	kc := []byte("key material")
	ttl := 5 * time.Minute

	cache.Put(query, response, kc, ttl)

	gotResp, gotKc, found := cache.Get(query)
	if !found {
		t.Fatal("expected to find cached entry")
	}
	if string(gotResp) != string(response) {
		t.Errorf("response mismatch: got %q, want %q", gotResp, response)
	}
	if string(gotKc) != string(kc) {
		t.Errorf("kc mismatch: got %q, want %q", gotKc, kc)
	}
}

func TestORAMCache_NotFound(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    1024,
		BucketSize:   4,
		ConstantTime: false,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		t.Fatalf("NewORAMCache failed: %v", err)
	}

	_, _, found := cache.Get("nonexistent.com.")
	if found {
		t.Error("expected not to find nonexistent entry")
	}
}

func TestORAMCache_TTLExpiry(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    1024,
		BucketSize:   4,
		ConstantTime: false,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		t.Fatalf("NewORAMCache failed: %v", err)
	}

	query := "expire.com."
	cache.Put(query, []byte("data"), nil, 1*time.Millisecond)

	time.Sleep(5 * time.Millisecond)

	_, _, found := cache.Get(query)
	if found {
		t.Error("expected entry to be expired")
	}
}

func TestORAMCache_Overwrite(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    1024,
		BucketSize:   4,
		ConstantTime: false,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		t.Fatalf("NewORAMCache failed: %v", err)
	}

	query := "update.com."
	cache.Put(query, []byte("v1"), nil, 5*time.Minute)
	cache.Put(query, []byte("v2"), nil, 5*time.Minute)

	resp, _, found := cache.Get(query)
	if !found {
		t.Fatal("expected to find entry")
	}
	if string(resp) != "v2" {
		t.Errorf("expected v2, got %s", resp)
	}
}

func TestORAMCache_StashSize(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    1024,
		BucketSize:   4,
		ConstantTime: false,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		t.Fatalf("NewORAMCache failed: %v", err)
	}

	// Stash size should be small initially
	stash := cache.StashSize()
	if stash < 0 {
		t.Errorf("stash size should be non-negative, got %d", stash)
	}

	// Do some operations
	for i := 0; i < 10; i++ {
		cache.Put("query"+string(rune('a'+i))+".com.", []byte("data"), nil, 5*time.Minute)
	}

	// Stash should still be manageable
	stash = cache.StashSize()
	t.Logf("Stash size after 10 puts: %d", stash)
}

func TestORAMCache_Clear(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    1024,
		BucketSize:   4,
		ConstantTime: false,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		t.Fatalf("NewORAMCache failed: %v", err)
	}

	cache.Put("test.com.", []byte("data"), nil, 5*time.Minute)
	if cache.Size() != 1 {
		t.Errorf("expected size 1, got %d", cache.Size())
	}

	cache.Clear()
	if cache.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", cache.Size())
	}

	_, _, found := cache.Get("test.com.")
	if found {
		t.Error("expected not to find entry after clear")
	}
}

func TestORAMCache_LargeEntry(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    256, // Small block size
		BucketSize:   4,
		ConstantTime: false,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		t.Fatalf("NewORAMCache failed: %v", err)
	}

	// Entry larger than block size should fail silently
	query := "large.com."
	largeData := make([]byte, 300)
	cache.Put(query, largeData, nil, 5*time.Minute)

	// Should not find entry (put failed)
	_, _, found := cache.Get(query)
	if found {
		t.Error("expected large entry to not be stored")
	}
}

func TestCacheInterface(t *testing.T) {
	// Test that both implementations satisfy Cache interface
	var _ Cache = (*LRUCache)(nil)
	var _ Cache = (*ORAMCache)(nil)
}
