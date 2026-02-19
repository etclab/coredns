package enclave

import (
	"testing"
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
	insertedAt := int64(1000)
	ttlSecs := uint32(300)

	cache.Put(query, response, insertedAt, ttlSecs)

	gotResp, found := cache.Get(query, 1100) // within TTL (1000+300=1300 > 1100)
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

	_, found := cache.Get("nonexistent.com.", 1000)
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
	cache.Put(query, []byte("data"), 100, 60) // InsertedAt=100, TTL=60s → expires at 160

	// Not expired: tLatest=150 (100+60=160, 160 < 150 is false)
	if _, found := cache.Get(query, 150); !found {
		t.Error("expected entry to still be valid at tLatest=150")
	}

	// Expired: tLatest=161 (160 < 161 is true)
	if _, found := cache.Get(query, 161); found {
		t.Error("expected entry to be expired at tLatest=161")
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
	cache.Put(query, []byte("v1"), 100, 300)
	cache.Put(query, []byte("v2"), 200, 300)

	resp, found := cache.Get(query, 250)
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
		cache.Put("query"+string(rune('a'+i))+".com.", []byte("data"), 1000, 300)
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

	cache.Put("test.com.", []byte("data"), 1000, 300)
	if cache.Size() != 1 {
		t.Errorf("expected size 1, got %d", cache.Size())
	}

	cache.Clear()
	if cache.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", cache.Size())
	}

	_, found := cache.Get("test.com.", 1000)
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
	cache.Put(query, largeData, 1000, 300)

	_, found := cache.Get(query, 1000)
	if found {
		t.Error("expected large entry to not be stored")
	}
}

func TestCacheInterface(t *testing.T) {
	var _ Cache = (*LRUCache)(nil)
	var _ Cache = (*ORAMCache)(nil)
}
