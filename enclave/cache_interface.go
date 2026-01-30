package enclave

import "time"

// Cache defines the interface for DNS response caching.
type Cache interface {
	Get(query string) (response []byte, kc []byte, found bool)
	Put(query string, response, kc []byte, ttl time.Duration)
	Size() int
	Clear()
	CleanExpired() int
}
