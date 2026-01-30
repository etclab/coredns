package enclave

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkLRUCache_Put(b *testing.B) {
	cache := NewLRUCache(10000)
	data := []byte("benchmark response data")
	ttl := 5 * time.Minute

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%10000)
		cache.Put(query, data, nil, ttl)
	}
}

func BenchmarkLRUCache_Get(b *testing.B) {
	cache := NewLRUCache(10000)
	data := []byte("benchmark response data")
	ttl := 5 * time.Minute

	// Pre-populate
	for i := 0; i < 10000; i++ {
		query := fmt.Sprintf("query%d.com.", i)
		cache.Put(query, data, nil, ttl)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%10000)
		cache.Get(query)
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
	ttl := 5 * time.Minute

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%10000)
		cache.Put(query, data, nil, ttl)
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
	ttl := 5 * time.Minute

	// Pre-populate
	for i := 0; i < 1000; i++ {
		query := fmt.Sprintf("query%d.com.", i)
		cache.Put(query, data, nil, ttl)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%1000)
		cache.Get(query)
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
	ttl := 5 * time.Minute

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%10000)
		cache.Put(query, data, nil, ttl)
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
	ttl := 5 * time.Minute

	// Pre-populate
	for i := 0; i < 1000; i++ {
		query := fmt.Sprintf("query%d.com.", i)
		cache.Put(query, data, nil, ttl)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := fmt.Sprintf("query%d.com.", i%1000)
		cache.Get(query)
	}
}
