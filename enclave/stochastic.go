package enclave

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"time"
)

// StochasticConfig holds configuration for stochastic cache defenses
type StochasticConfig struct {
	HitSuppressionProb float64       // p_fn: probability of suppressing a cache hit [0.0, 1.0]
	InsertProb         float64       // p_ins: probability of inserting an entry [0.0, 1.0]
	ChurnInterval      time.Duration // interval for random churn
	ChurnEnabled       bool          // whether churn is enabled
}

// DefaultStochasticConfig returns a config with all defenses disabled
func DefaultStochasticConfig() StochasticConfig {
	return StochasticConfig{
		HitSuppressionProb: 0.0,
		InsertProb:         1.0,
		ChurnInterval:      0,
		ChurnEnabled:       false,
	}
}

// SecureRNG provides cryptographically secure random numbers using crypto/rand
// In SGX, this uses RDRAND instruction
type SecureRNG struct{}

// NewSecureRNG creates a new secure RNG
func NewSecureRNG() *SecureRNG {
	return &SecureRNG{}
}

// Float64 returns a random float64 in [0.0, 1.0) using crypto/rand
func (r *SecureRNG) Float64() float64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		log.Printf("SecureRNG: failed to read random bytes: %v", err)
		return 0.0
	}
	// Convert to uint64 and normalize to [0.0, 1.0)
	u := binary.LittleEndian.Uint64(buf[:])
	return float64(u) / float64(1<<64)
}

// ShouldSuppressHit returns true if a cache hit should be suppressed (false negative)
func (cfg *StochasticConfig) ShouldSuppressHit(rng *SecureRNG) bool {
	if cfg.HitSuppressionProb <= 0.0 {
		return false
	}
	return rng.Float64() < cfg.HitSuppressionProb
}

// ShouldInsert returns true if an entry should be inserted into cache
func (cfg *StochasticConfig) ShouldInsert(rng *SecureRNG) bool {
	if cfg.InsertProb >= 1.0 {
		return true
	}
	return rng.Float64() < cfg.InsertProb
}
