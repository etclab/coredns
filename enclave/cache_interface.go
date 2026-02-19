package enclave

// Cache defines the interface for DNS response caching.
// Cache stores plaintext DNS responses. Re-encryption under session keys
// happens at the handler level (e.g., EncryptCachedResponse with k_r).
// Expiry uses logical time (tLatest) rather than wall-clock time.
type Cache interface {
	Get(query string, tLatest int64) (response []byte, found bool)
	Put(query string, response []byte, insertedAt int64, ttlSecs uint32)
	Size() int
	Clear()
	CleanExpired(tLatest int64) int
	PutBatch(entries []PendingInsert)
}
