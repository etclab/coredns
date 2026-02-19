package enclave

import (
	"container/list"
	"sync"
	"time"
)

// CacheEntry holds a cached DNS response.
type CacheEntry struct {
	Query     string    // Canonicalized query key
	Response  []byte    // Plaintext DNS response
	ExpiresAt time.Time // TTL expiry
}

// LRUCache implements an LRU cache with TTL for DNS responses.
type LRUCache struct {
	capacity int
	cache    map[string]*list.Element // query -> list element
	lru      *list.List               // front = most recent, back = least recent
	mu       sync.RWMutex
}

// NewLRUCache creates a new LRU cache with the given capacity.
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		lru:      list.New(),
	}
}

// Get retrieves a cached response for the given query.
// Returns the plaintext response if found and not expired.
func (c *LRUCache) Get(query string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.cache[query]
	if !ok {
		return nil, false
	}

	entry := elem.Value.(*CacheEntry)

	// Check TTL
	if time.Now().After(entry.ExpiresAt) {
		c.removeElement(elem)
		return nil, false
	}

	// Move to front (most recently used)
	c.lru.MoveToFront(elem)

	return entry.Response, true
}

// Put stores a plaintext DNS response in the cache.
func (c *LRUCache) Put(query string, response []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already exists
	if elem, ok := c.cache[query]; ok {
		entry := elem.Value.(*CacheEntry)
		entry.Response = response
		entry.ExpiresAt = time.Now().Add(ttl)
		c.lru.MoveToFront(elem)
		return
	}

	// Evict if at capacity
	if c.lru.Len() >= c.capacity {
		c.evictOldest()
	}

	entry := &CacheEntry{
		Query:     query,
		Response:  response,
		ExpiresAt: time.Now().Add(ttl),
	}
	elem := c.lru.PushFront(entry)
	c.cache[query] = elem
}

// evictOldest removes the least recently used entry.
func (c *LRUCache) evictOldest() {
	elem := c.lru.Back()
	if elem != nil {
		c.removeElement(elem)
	}
}

// removeElement removes an element from the cache.
func (c *LRUCache) removeElement(elem *list.Element) {
	entry := elem.Value.(*CacheEntry)
	delete(c.cache, entry.Query)
	c.lru.Remove(elem)
}

// Size returns the current number of entries in the cache.
func (c *LRUCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lru.Len()
}

// Clear removes all entries from the cache.
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*list.Element)
	c.lru.Init()
}

// Compile-time interface check
var _ Cache = (*LRUCache)(nil)

// CleanExpired removes all expired entries from the cache.
func (c *LRUCache) CleanExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for elem := c.lru.Back(); elem != nil; {
		entry := elem.Value.(*CacheEntry)
		prev := elem.Prev()

		if now.After(entry.ExpiresAt) {
			c.removeElement(elem)
			removed++
		}

		elem = prev
	}

	return removed
}
