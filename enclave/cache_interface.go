package enclave

import "time"

// Cache defines the interface for DNS response caching.
// Cache stores plaintext DNS responses. Re-encryption under session keys
// happens at the handler level (e.g., EncryptCachedResponse with k_r).
type Cache interface {
	Get(query string) (response []byte, found bool)
	Put(query string, response []byte, ttl time.Duration)
	Size() int
	Clear()
	CleanExpired() int
}
