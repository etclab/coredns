package enclave

import (
	"fmt"
	"testing"
)

func BenchmarkLRUCache_Put(b *testing.B) {
	cache := NewLRUCache(10000)
	data := []byte("benchmark response data")
	insertedAt := int64(1000000)
	ttlSecs := uint32(300)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%10000)
		cache.Put(query, data, insertedAt, ttlSecs)
	}
}

func BenchmarkLRUCache_Get(b *testing.B) {
	cache := NewLRUCache(10000)
	data := []byte("benchmark response data")
	insertedAt := int64(1000000)
	ttlSecs := uint32(300)

	// Pre-populate
	for i := 0; i < 10000; i++ {
		query := fmt.Sprintf("query%d.com.", i)
		cache.Put(query, data, insertedAt, ttlSecs)
	}

	tLatest := int64(1000100) // within TTL

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%10000)
		cache.Get(query, tLatest)
	}
}

func BenchmarkORAMCache_Put(b *testing.B) {
	cfg := ORAMCacheConfig{
		Capacity:     10000,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		b.Fatalf("NewORAMCache failed: %v", err)
	}
	data := []byte("benchmark response data")
	insertedAt := int64(1000000)
	ttlSecs := uint32(300)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%10000)
		cache.Put(query, data, insertedAt, ttlSecs)
	}
}

func BenchmarkORAMCache_Get(b *testing.B) {
	cfg := ORAMCacheConfig{
		Capacity:     10000,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: false,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		b.Fatalf("NewORAMCache failed: %v", err)
	}
	data := []byte("benchmark response data")
	insertedAt := int64(1000000)
	ttlSecs := uint32(300)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		query := fmt.Sprintf("query%d.com.", i)
		cache.Put(query, data, insertedAt, ttlSecs)
	}

	tLatest := int64(1000100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%1000)
		cache.Get(query, tLatest)
	}
}

func BenchmarkORAMCache_ConstantTime_Put(b *testing.B) {
	cfg := ORAMCacheConfig{
		Capacity:     10000,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: true,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		b.Fatalf("NewORAMCache failed: %v", err)
	}
	data := []byte("benchmark response data")
	insertedAt := int64(1000000)
	ttlSecs := uint32(300)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%10000)
		cache.Put(query, data, insertedAt, ttlSecs)
	}
}

func BenchmarkORAMCache_ConstantTime_Get(b *testing.B) {
	cfg := ORAMCacheConfig{
		Capacity:     10000,
		BlockSize:    4096,
		BucketSize:   4,
		ConstantTime: true,
	}
	cache, err := NewORAMCache(cfg)
	if err != nil {
		b.Fatalf("NewORAMCache failed: %v", err)
	}
	data := []byte("benchmark response data")
	insertedAt := int64(1000000)
	ttlSecs := uint32(300)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		query := fmt.Sprintf("query%d.com.", i)
		cache.Put(query, data, insertedAt, ttlSecs)
	}

	tLatest := int64(1000100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%1000)
		cache.Get(query, tLatest)
	}
}
