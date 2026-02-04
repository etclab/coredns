package enclave

import (
	"crypto/sha256"
	"encoding/binary"
	"log"
	"sync"
	"time"

	"github.com/etclab/pathoram-go"
)

// MLECache implements a tag-based cache for MLE entries using ORAM.
// The enclave stores only (tag, exp, ciphertext) and cannot decrypt.
type MLECache struct {
	oram       *pathoram.PathORAM
	cfg        ORAMCacheConfig
	mu         sync.Mutex
	used       map[int]bool // Track which block IDs are in use
	stochastic StochasticConfig
	rng        *SecureRNG
	stopChurn  chan struct{}
}

// NewMLECache creates a new MLE cache with default stochastic config.
func NewMLECache(cfg ORAMCacheConfig) (*MLECache, error) {
	return NewMLECacheWithStochastic(cfg, DefaultStochasticConfig())
}

// NewMLECacheWithStochastic creates a new MLE cache with stochastic defenses.
func NewMLECacheWithStochastic(cfg ORAMCacheConfig, stochastic StochasticConfig) (*MLECache, error) {
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

	cache := &MLECache{
		oram:       oram,
		cfg:        cfg,
		used:       make(map[int]bool),
		stochastic: stochastic,
		rng:        NewSecureRNG(),
		stopChurn:  make(chan struct{}),
	}

	if stochastic.ChurnEnabled && stochastic.ChurnInterval > 0 {
		go cache.churnLoop()
	}

	return cache, nil
}

// tagToBlockID maps a 16-byte tag to a block ID using SHA256.
func (c *MLECache) tagToBlockID(tag [16]byte) int {
	h := sha256.Sum256(tag[:])
	// Use first 8 bytes as uint64, mod capacity
	n := binary.BigEndian.Uint64(h[:8])
	return int(n % uint64(c.cfg.Capacity))
}

// Get retrieves a cached entry by tag.
// Returns the entry and true if found and not expired.
func (c *MLECache) Get(tag [16]byte) (*MLECacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	blockID := c.tagToBlockID(tag)
	data, err := c.oram.Read(blockID)
	if err != nil {
		log.Printf("MLECache.Get: read error: %v", err)
		return nil, false
	}

	entry, ok := c.deserializeMLEEntry(data)
	if !ok || entry.Tag != tag {
		// Empty block or hash collision
		return nil, false
	}

	// Check expiry
	if time.Now().Unix() >= entry.Exp {
		return nil, false
	}

	// Apply stochastic hit suppression
	if c.stochastic.ShouldSuppressHit(c.rng) {
		log.Printf("MLECache: suppressing hit (p_fn=%.2f)", c.stochastic.HitSuppressionProb)
		return nil, false
	}

	return entry, true
}

// Put stores an MLE cache entry.
func (c *MLECache) Put(entry *MLECacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Apply stochastic non-insertion
	if !c.stochastic.ShouldInsert(c.rng) {
		log.Printf("MLECache: skipping insert (p_ins=%.2f)", c.stochastic.InsertProb)
		return
	}

	blockID := c.tagToBlockID(entry.Tag)

	data, ok := c.serializeMLEEntry(entry)
	if !ok {
		log.Printf("MLECache.Put: entry too large for block size")
		return
	}

	if _, err := c.oram.Write(blockID, data); err != nil {
		log.Printf("MLECache.Put: write error: %v", err)
		return
	}

	c.used[blockID] = true
}

// serializeMLEEntry encodes an MLECacheEntry into a fixed-size block.
// Format: [valid:1][tag:16][exp:8][ctLen:2][ciphertext]
func (c *MLECache) serializeMLEEntry(entry *MLECacheEntry) ([]byte, bool) {
	// Calculate required size: 1 + 16 + 8 + 2 + len(ciphertext)
	requiredSize := 1 + 16 + 8 + 2 + len(entry.Ciphertext)
	if requiredSize > c.cfg.BlockSize {
		return nil, false
	}

	buf := make([]byte, c.cfg.BlockSize)
	offset := 0

	// Valid marker
	buf[offset] = 1
	offset++

	// Tag (16 bytes)
	copy(buf[offset:], entry.Tag[:])
	offset += 16

	// Exp (8 bytes, big-endian)
	binary.BigEndian.PutUint64(buf[offset:], uint64(entry.Exp))
	offset += 8

	// Ciphertext length (2 bytes)
	if len(entry.Ciphertext) > 65535 {
		return nil, false
	}
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(entry.Ciphertext)))
	offset += 2

	// Ciphertext
	copy(buf[offset:], entry.Ciphertext)

	return buf, true
}

// deserializeMLEEntry decodes an MLECacheEntry from a block.
func (c *MLECache) deserializeMLEEntry(data []byte) (*MLECacheEntry, bool) {
	// Minimum size: 1 + 16 + 8 + 2 = 27 bytes
	if len(data) < 27 {
		return nil, false
	}

	// Check valid marker
	if data[0] != 1 {
		return nil, false
	}
	offset := 1

	entry := &MLECacheEntry{}

	// Tag (16 bytes)
	copy(entry.Tag[:], data[offset:offset+16])
	offset += 16

	// Exp (8 bytes, big-endian)
	entry.Exp = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	// Ciphertext length (2 bytes)
	ctLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+int(ctLen) > len(data) {
		return nil, false
	}

	// Ciphertext
	entry.Ciphertext = make([]byte, ctLen)
	copy(entry.Ciphertext, data[offset:offset+int(ctLen)])

	return entry, true
}

// Size returns approximate number of entries.
func (c *MLECache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.used)
}

// StashSize returns the current ORAM stash size (for monitoring).
func (c *MLECache) StashSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.oram.StashSize()
}

// Clear resets the cache (re-creates ORAM).
func (c *MLECache) Clear() {
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
		log.Printf("MLECache.Clear: failed to recreate ORAM: %v", err)
		return
	}

	c.oram = oram
	c.used = make(map[int]bool)
}

// churnLoop periodically evicts a random cache entry.
func (c *MLECache) churnLoop() {
	ticker := time.NewTicker(c.stochastic.ChurnInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.churnOnce()
		case <-c.stopChurn:
			return
		}
	}
}

// churnOnce evicts a random cache entry.
func (c *MLECache) churnOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.used) == 0 {
		return
	}

	// Pick a random block to evict
	blockID := int(c.rng.Float64() * float64(c.cfg.Capacity))
	emptyBlock := make([]byte, c.cfg.BlockSize)
	if _, err := c.oram.Write(blockID, emptyBlock); err != nil {
		log.Printf("MLECache: churn write error: %v", err)
		return
	}
	delete(c.used, blockID)

	log.Printf("MLECache: churned block %d, size=%d", blockID, len(c.used))
}

// StopChurn stops the churn loop.
func (c *MLECache) StopChurn() {
	if c.stopChurn != nil {
		close(c.stopChurn)
	}
}
