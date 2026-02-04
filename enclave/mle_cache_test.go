package enclave

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestNewMLECache(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}

	cache, err := NewMLECache(cfg)
	if err != nil {
		t.Fatalf("NewMLECache failed: %v", err)
	}

	if cache.Size() != 0 {
		t.Errorf("Expected empty cache, got size %d", cache.Size())
	}
}

func TestMLECachePutGet(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}

	cache, _ := NewMLECache(cfg)

	// Create entry
	var tag [16]byte
	copy(tag[:], []byte("0123456789abcdef"))

	entry := &MLECacheEntry{
		Tag:        tag,
		Exp:        time.Now().Unix() + 3600, // 1 hour from now
		Ciphertext: []byte("encrypted DNS response data here"),
	}

	// Store
	cache.Put(entry)

	if cache.Size() != 1 {
		t.Errorf("Expected size 1, got %d", cache.Size())
	}

	// Retrieve
	retrieved, ok := cache.Get(tag)
	if !ok {
		t.Fatal("Get returned false for existing entry")
	}

	if retrieved.Tag != tag {
		t.Error("Tag mismatch")
	}
	if retrieved.Exp != entry.Exp {
		t.Errorf("Exp mismatch: expected %d, got %d", entry.Exp, retrieved.Exp)
	}
	if !bytes.Equal(retrieved.Ciphertext, entry.Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
}

func TestMLECacheExpiry(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}

	cache, _ := NewMLECache(cfg)

	// Create expired entry
	var tag [16]byte
	copy(tag[:], []byte("expired_entry!!!"))

	entry := &MLECacheEntry{
		Tag:        tag,
		Exp:        time.Now().Unix() - 1, // Already expired
		Ciphertext: []byte("old data"),
	}

	cache.Put(entry)

	// Should not retrieve expired entry
	_, ok := cache.Get(tag)
	if ok {
		t.Error("Should not retrieve expired entry")
	}
}

func TestMLECacheMiss(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}

	cache, _ := NewMLECache(cfg)

	var tag [16]byte
	copy(tag[:], []byte("nonexistent_tag!"))

	_, ok := cache.Get(tag)
	if ok {
		t.Error("Get should return false for nonexistent tag")
	}
}

func TestMLECacheOverwrite(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}

	cache, _ := NewMLECache(cfg)

	var tag [16]byte
	copy(tag[:], []byte("overwrite_test!!"))

	// Store first entry
	entry1 := &MLECacheEntry{
		Tag:        tag,
		Exp:        time.Now().Unix() + 3600,
		Ciphertext: []byte("first data"),
	}
	cache.Put(entry1)

	// Store second entry with same tag
	entry2 := &MLECacheEntry{
		Tag:        tag,
		Exp:        time.Now().Unix() + 7200,
		Ciphertext: []byte("second data - different"),
	}
	cache.Put(entry2)

	// Should get second entry
	retrieved, ok := cache.Get(tag)
	if !ok {
		t.Fatal("Get failed")
	}

	if !bytes.Equal(retrieved.Ciphertext, entry2.Ciphertext) {
		t.Error("Should have overwritten with second entry")
	}
}

func TestMLECacheStashSize(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}

	cache, _ := NewMLECache(cfg)

	// Stash size should be >= 0
	stashSize := cache.StashSize()
	if stashSize < 0 {
		t.Errorf("Stash size should be non-negative, got %d", stashSize)
	}
}

func TestMLECacheClear(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}

	cache, _ := NewMLECache(cfg)

	// Add some entries
	for i := 0; i < 10; i++ {
		var tag [16]byte
		rand.Read(tag[:])

		entry := &MLECacheEntry{
			Tag:        tag,
			Exp:        time.Now().Unix() + 3600,
			Ciphertext: []byte("test data"),
		}
		cache.Put(entry)
	}

	if cache.Size() == 0 {
		t.Error("Expected non-empty cache before clear")
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected empty cache after clear, got %d", cache.Size())
	}
}

func TestMLECacheSerializationLargeEntry(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    256, // Small block size
		BucketSize:   4,
		ConstantTime: false,
	}

	cache, _ := NewMLECache(cfg)

	// Try to store entry too large for block size
	var tag [16]byte
	copy(tag[:], []byte("large_entry_test"))

	entry := &MLECacheEntry{
		Tag:        tag,
		Exp:        time.Now().Unix() + 3600,
		Ciphertext: make([]byte, 300), // Larger than block size
	}

	// Should not panic, just log and skip
	cache.Put(entry)

	// Entry should not be stored
	_, ok := cache.Get(tag)
	if ok {
		t.Error("Large entry should not be stored")
	}
}

func TestMLECacheStochasticHitSuppression(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}

	// 100% hit suppression
	stochastic := StochasticConfig{
		HitSuppressionProb: 1.0,
		InsertProb:         1.0,
	}

	cache, _ := NewMLECacheWithStochastic(cfg, stochastic)

	var tag [16]byte
	copy(tag[:], []byte("suppression_test"))

	entry := &MLECacheEntry{
		Tag:        tag,
		Exp:        time.Now().Unix() + 3600,
		Ciphertext: []byte("test data"),
	}

	cache.Put(entry)

	// With p_fn=1.0, all hits should be suppressed
	_, ok := cache.Get(tag)
	if ok {
		t.Error("Hit should be suppressed with p_fn=1.0")
	}
}

func TestMLECacheStochasticNonInsertion(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}

	// 0% insertion probability
	stochastic := StochasticConfig{
		HitSuppressionProb: 0.0,
		InsertProb:         0.0,
	}

	cache, _ := NewMLECacheWithStochastic(cfg, stochastic)

	var tag [16]byte
	copy(tag[:], []byte("noinsert_test!!"))

	entry := &MLECacheEntry{
		Tag:        tag,
		Exp:        time.Now().Unix() + 3600,
		Ciphertext: []byte("test data"),
	}

	cache.Put(entry)

	// With p_ins=0.0, nothing should be stored
	_, ok := cache.Get(tag)
	if ok {
		t.Error("Entry should not be stored with p_ins=0.0")
	}

	if cache.Size() != 0 {
		t.Errorf("Cache should be empty with p_ins=0.0, got size %d", cache.Size())
	}
}

func TestMLECacheTagToBlockID(t *testing.T) {
	cfg := ORAMCacheConfig{
		Capacity:     1000,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}

	cache, _ := NewMLECache(cfg)

	// Same tag should map to same block ID
	var tag [16]byte
	copy(tag[:], []byte("consistent_tag!!"))

	blockID1 := cache.tagToBlockID(tag)
	blockID2 := cache.tagToBlockID(tag)

	if blockID1 != blockID2 {
		t.Error("Same tag should map to same block ID")
	}

	// Block ID should be within capacity
	if blockID1 < 0 || blockID1 >= cfg.Capacity {
		t.Errorf("Block ID %d out of range [0, %d)", blockID1, cfg.Capacity)
	}

	// Different tags should likely map to different block IDs
	var tag2 [16]byte
	copy(tag2[:], []byte("different_tag!!!"))

	blockID3 := cache.tagToBlockID(tag2)
	// Note: collision is possible but unlikely
	if blockID1 == blockID3 {
		t.Log("Tags collided to same block ID (unlikely but possible)")
	}
}
