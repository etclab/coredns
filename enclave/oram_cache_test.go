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

	query := "example.com."
	response := []byte("dns response data")
	ttl := 5 * time.Minute

	cache.Put(query, response, ttl)

	gotResp, found := cache.Get(query)
	if !found {
		t.Fatal("expected to find cached entry")
	}
	if string(gotResp) != string(response) {
		t.Errorf("response mismatch: got %q, want %q", gotResp, response)
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

	_, found := cache.Get("nonexistent.com.")
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
	cache.Put(query, []byte("data"), 1*time.Millisecond)

	time.Sleep(5 * time.Millisecond)

	_, found := cache.Get(query)
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
	cache.Put(query, []byte("v1"), 5*time.Minute)
	cache.Put(query, []byte("v2"), 5*time.Minute)

	resp, found := cache.Get(query)
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

	stash := cache.StashSize()
	if stash < 0 {
		t.Errorf("stash size should be non-negative, got %d", stash)
	}

	for i := 0; i < 10; i++ {
		cache.Put("query"+string(rune('a'+i))+".com.", []byte("data"), 5*time.Minute)
	}

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

	cache.Put("test.com.", []byte("data"), 5*time.Minute)
	if cache.Size() != 1 {
		t.Errorf("expected size 1, got %d", cache.Size())
	}

	cache.Clear()
	if cache.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", cache.Size())
	}

	_, found := cache.Get("test.com.")
	if found {
		t.Error("expected not to find entry after clear")
	}
}

func TestORAMCache_LargeEntry(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    256,
		BucketSize:   4,
		ConstantTime: false,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		t.Fatalf("NewORAMCache failed: %v", err)
	}

	query := "large.com."
	largeData := make([]byte, 300)
	cache.Put(query, largeData, 5*time.Minute)

	_, found := cache.Get(query)
	if found {
		t.Error("expected large entry to not be stored")
	}
}

func TestCacheInterface(t *testing.T) {
	var _ Cache = (*LRUCache)(nil)
	var _ Cache = (*ORAMCache)(nil)
}
