package enclave

import (
	"fmt"
	"testing"
)

var cacheSizes = []int{256, 512, 1024, 2048}

func BenchmarkLRUCache_Put(b *testing.B) {
	for _, n := range cacheSizes {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			cache := NewLRUCache(n)
			data := []byte("benchmark response data")
			insertedAt := int64(1000000)
			ttlSecs := uint32(300)

			// Pre-populate with N/2 entries
			for i := 0; i < n/2; i++ {
				cache.Put(fmt.Sprintf("pre%d.com.", i), data, insertedAt, ttlSecs)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				query := fmt.Sprintf("query%d.com.", i%n)
				cache.Put(query, data, insertedAt, ttlSecs)
			}
		})
	}
}

func BenchmarkLRUCache_Get(b *testing.B) {
	for _, n := range cacheSizes {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			cache := NewLRUCache(n)
			data := []byte("benchmark response data")
			insertedAt := int64(1000000)
			ttlSecs := uint32(300)

			// Pre-populate with N/2 entries
			for i := 0; i < n/2; i++ {
				cache.Put(fmt.Sprintf("query%d.com.", i), data, insertedAt, ttlSecs)
			}

			tLatest := int64(1000100)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				query := fmt.Sprintf("query%d.com.", i%(n/2))
				cache.Get(query, tLatest)
			}
		})
	}
}

func BenchmarkORAMCache_Put(b *testing.B) {
	for _, n := range cacheSizes {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			cfg := ORAMCacheConfig{
				Capacity:     n,
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

			// Pre-populate with N/2 entries
			for i := 0; i < n/2; i++ {
				cache.Put(fmt.Sprintf("pre%d.com.", i), data, insertedAt, ttlSecs)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				query := fmt.Sprintf("query%d.com.", i%n)
				cache.Put(query, data, insertedAt, ttlSecs)
			}
		})
	}
}

func BenchmarkORAMCache_Get(b *testing.B) {
	for _, n := range cacheSizes {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			cfg := ORAMCacheConfig{
				Capacity:     n,
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

			// Pre-populate with N/2 entries
			for i := 0; i < n/2; i++ {
				cache.Put(fmt.Sprintf("query%d.com.", i), data, insertedAt, ttlSecs)
			}

			tLatest := int64(1000100)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				query := fmt.Sprintf("query%d.com.", i%(n/2))
				cache.Get(query, tLatest)
			}
		})
	}
}