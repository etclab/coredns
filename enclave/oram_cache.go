package enclave

import (
	"encoding/binary"
	"hash/fnv"
	"log"
	"sync"
	"time"

	"github.com/etclab/pathoram-go"
)

// ORAMCache wraps PathORAM to implement the Cache interface.
// Provides access-pattern hiding at the cost of performance.
type ORAMCache struct {
	oram      *pathoram.PathORAM
	cfg       ORAMCacheConfig
	mu        sync.Mutex

	// Track which block IDs are in use (for Size())
	used map[int]bool
}

// ORAMCacheConfig configures the ORAM cache.
type ORAMCacheConfig struct {
	Capacity     int // Number of cache entries
	BlockSize    int // Block size in bytes (must fit serialized entry)
	BucketSize   int // Blocks per bucket (Z parameter)
	ConstantTime bool // Enable constant-time operations for TEE
}

// DefaultORAMCacheConfig returns default ORAM cache configuration.
func DefaultORAMCacheConfig() ORAMCacheConfig {
	return ORAMCacheConfig{
		Capacity:     10000,
		BlockSize:    4096, // 4KB blocks
		BucketSize:   4,
		ConstantTime: true, // Default to constant-time for enclave
	}
}

// NewORAMCache creates a new ORAM-backed cache.
func NewORAMCache(cfg ORAMCacheConfig) (*ORAMCache, error) {
	oramCfg := pathoram.Config{
		NumBlocks:    cfg.Capacity,
		BlockSize:    cfg.BlockSize,
		BucketSize:   cfg.BucketSize,
		ConstantTime: cfg.ConstantTime,
	}

	oram, err := pathoram.NewInMemory(oramCfg)
	if err != nil {
		return nil, err
	}

	return &ORAMCache{
		oram: oram,
		cfg:  cfg,
		used: make(map[int]bool),
	}, nil
}

// Get retrieves a cached response for the given query.
func (c *ORAMCache) Get(query string) ([]byte, []byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	blockID := c.queryToBlockID(query)
	data, err := c.oram.Read(blockID)
	if err != nil {
		log.Printf("ORAMCache.Get: read error: %v", err)
		return nil, nil, false
	}

	entry, ok := c.deserialize(data)
	if !ok || entry.Query != query {
		// Empty block or hash collision
		return nil, nil, false
	}

	// Check TTL
	if time.Now().After(entry.ExpiresAt) {
		return nil, nil, false
	}

	return entry.Response, entry.Kc, true
}

// Put stores a response in the cache.
func (c *ORAMCache) Put(query string, response, kc []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	blockID := c.queryToBlockID(query)
	entry := &CacheEntry{
		Query:     query,
		Response:  response,
		Kc:        kc,
		ExpiresAt: time.Now().Add(ttl),
	}

	data, ok := c.serialize(entry)
	if !ok {
		log.Printf("ORAMCache.Put: entry too large for block size")
		return
	}

	if _, err := c.oram.Write(blockID, data); err != nil {
		log.Printf("ORAMCache.Put: write error: %v", err)
		return
	}

	c.used[blockID] = true
}

// Size returns approximate number of entries.
func (c *ORAMCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.used)
}

// Clear resets the cache (re-creates ORAM).
func (c *ORAMCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	oramCfg := pathoram.Config{
		NumBlocks:    c.cfg.Capacity,
		BlockSize:    c.cfg.BlockSize,
		BucketSize:   c.cfg.BucketSize,
		ConstantTime: c.cfg.ConstantTime,
	}

	oram, err := pathoram.NewInMemory(oramCfg)
	if err != nil {
		log.Printf("ORAMCache.Clear: failed to recreate ORAM: %v", err)
		return
	}

	c.oram = oram
	c.used = make(map[int]bool)
}

// CleanExpired is a no-op for ORAM cache (entries expire on access).
func (c *ORAMCache) CleanExpired() int {
	return 0
}

// StashSize returns the current ORAM stash size (for monitoring).
func (c *ORAMCache) StashSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.oram.StashSize()
}

// queryToBlockID maps a query string to a block ID using FNV hash.
func (c *ORAMCache) queryToBlockID(query string) int {
	h := fnv.New64a()
	h.Write([]byte(query))
	return int(h.Sum64() % uint64(c.cfg.Capacity))
}

// serialize encodes a CacheEntry into a fixed-size block.
// Format: [queryLen:2][query][respLen:2][resp][kcLen:2][kc][expiresUnix:8][valid:1]
func (c *ORAMCache) serialize(entry *CacheEntry) ([]byte, bool) {
	buf := make([]byte, c.cfg.BlockSize)
	offset := 0

	// Query length + data
	if len(entry.Query) > 65535 {
		return nil, false
	}
	queryLen := uint16(len(entry.Query))
	binary.LittleEndian.PutUint16(buf[offset:], queryLen)
	offset += 2
	if offset+int(queryLen) > c.cfg.BlockSize {
		return nil, false
	}
	copy(buf[offset:], entry.Query)
	offset += int(queryLen)

	// Response length + data
	if len(entry.Response) > 65535 {
		return nil, false
	}
	respLen := uint16(len(entry.Response))
	binary.LittleEndian.PutUint16(buf[offset:], respLen)
	offset += 2
	if offset+int(respLen) > c.cfg.BlockSize {
		return nil, false
	}
	copy(buf[offset:], entry.Response)
	offset += int(respLen)

	// Kc length + data
	if len(entry.Kc) > 65535 {
		return nil, false
	}
	kcLen := uint16(len(entry.Kc))
	binary.LittleEndian.PutUint16(buf[offset:], kcLen)
	offset += 2
	if offset+int(kcLen) > c.cfg.BlockSize {
		return nil, false
	}
	copy(buf[offset:], entry.Kc)
	offset += int(kcLen)

	// Expires timestamp (Unix nanos)
	if offset+8 > c.cfg.BlockSize {
		return nil, false
	}
	binary.LittleEndian.PutUint64(buf[offset:], uint64(entry.ExpiresAt.UnixNano()))
	offset += 8

	// Valid marker
	if offset+1 > c.cfg.BlockSize {
		return nil, false
	}
	buf[offset] = 1

	return buf, true
}

// deserialize decodes a CacheEntry from a block.
func (c *ORAMCache) deserialize(data []byte) (*CacheEntry, bool) {
	if len(data) < 1 {
		return nil, false
	}

	// Check for empty block (all zeros)
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, false
	}

	offset := 0

	// Query
	if offset+2 > len(data) {
		return nil, false
	}
	queryLen := binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(queryLen) > len(data) {
		return nil, false
	}
	query := string(data[offset : offset+int(queryLen)])
	offset += int(queryLen)

	// Response
	if offset+2 > len(data) {
		return nil, false
	}
	respLen := binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(respLen) > len(data) {
		return nil, false
	}
	response := make([]byte, respLen)
	copy(response, data[offset:offset+int(respLen)])
	offset += int(respLen)

	// Kc
	if offset+2 > len(data) {
		return nil, false
	}
	kcLen := binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(kcLen) > len(data) {
		return nil, false
	}
	kc := make([]byte, kcLen)
	copy(kc, data[offset:offset+int(kcLen)])
	offset += int(kcLen)

	// Expires
	if offset+8 > len(data) {
		return nil, false
	}
	expiresNano := binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	// Valid marker
	if offset+1 > len(data) || data[offset] != 1 {
		return nil, false
	}

	return &CacheEntry{
		Query:     query,
		Response:  response,
		Kc:        kc,
		ExpiresAt: time.Unix(0, int64(expiresNano)),
	}, true
}

// Compile-time interface check
var _ Cache = (*ORAMCache)(nil)