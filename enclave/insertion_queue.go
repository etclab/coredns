package enclave

import "sync"

// PendingInsert represents a cache entry waiting to be committed.
type PendingInsert struct {
	Query      string
	Response   []byte
	TTL        uint32
	InsertedAt int64
}

// InsertionQueue is a bounded FIFO queue for pending cache inserts.
// Thread-safe. On overflow, the oldest entry is evicted (head-drop).
type InsertionQueue struct {
	entries []PendingInsert
	mu      sync.Mutex
	maxSize int
}

// NewInsertionQueue creates a new InsertionQueue with the given max size.
func NewInsertionQueue(maxSize int) *InsertionQueue {
	return &InsertionQueue{
		entries: make([]PendingInsert, 0, maxSize),
		maxSize: maxSize,
	}
}

// Enqueue adds an entry. If full, evicts the oldest entry first.
// Returns true if an eviction occurred.
func (q *InsertionQueue) Enqueue(p PendingInsert) (evicted bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.entries) >= q.maxSize {
		// Head-drop: evict oldest (index 0)
		q.entries = q.entries[1:]
		evicted = true
	}
	q.entries = append(q.entries, p)
	return evicted
}

// Len returns the current queue depth.
func (q *InsertionQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.entries)
}

// DrainBatch removes and returns up to n entries from the front.
func (q *InsertionQueue) DrainBatch(n int) []PendingInsert {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.entries) == 0 {
		return nil
	}
	if n > len(q.entries) {
		n = len(q.entries)
	}

	batch := make([]PendingInsert, n)
	copy(batch, q.entries[:n])
	q.entries = q.entries[n:]
	return batch
}
