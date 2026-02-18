package enclave

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"time"
)

// StochasticConfig holds configuration for stochastic cache defenses.
// After Sprint 1, only churn remains. Hit suppression and insert probability
// are replaced by batching (Sprint 4) and cover responses (Sprint 5).
type StochasticConfig struct {
	ChurnInterval time.Duration // interval for random churn
	ChurnEnabled  bool          // whether churn is enabled
}

// DefaultStochasticConfig returns a config with all defenses disabled.
func DefaultStochasticConfig() StochasticConfig {
	return StochasticConfig{
		ChurnInterval: 0,
		ChurnEnabled:  false,
	}
}

// SecureRNG provides cryptographically secure random numbers using crypto/rand.
// In SGX, this uses RDRAND instruction.
type SecureRNG struct{}

// NewSecureRNG creates a new secure RNG.
func NewSecureRNG() *SecureRNG {
	return &SecureRNG{}
}

// Float64 returns a random float64 in [0.0, 1.0) using crypto/rand.
func (r *SecureRNG) Float64() float64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		log.Printf("SecureRNG: failed to read random bytes: %v", err)
		return 0.0
	}
	u := binary.LittleEndian.Uint64(buf[:])
	return float64(u) / float64(1<<64)
}
