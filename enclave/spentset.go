package enclave

import (
	"crypto/sha256"
	"sync"
)

// SpentSet tracks spent tokens to prevent replay attacks.
// Cleared on epoch rotation.
type SpentSet struct {
	tokens map[[32]byte]struct{}
	epoch  uint32
	mu     sync.RWMutex
}

// NewSpentSet creates a new spent set for the given epoch.
func NewSpentSet(epoch uint32) *SpentSet {
	return &SpentSet{
		tokens: make(map[[32]byte]struct{}),
		epoch:  epoch,
	}
}

// MarkSpent attempts to mark a token as spent.
// Returns true if successfully marked (token was not already spent).
// Returns false if token was already spent (replay detected).
func (s *SpentSet) MarkSpent(token []byte) bool {
	hash := sha256.Sum256(token)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tokens[hash]; exists {
		return false // already spent
	}

	s.tokens[hash] = struct{}{}
	return true
}

// IsSpent checks if a token has been spent.
func (s *SpentSet) IsSpent(token []byte) bool {
	hash := sha256.Sum256(token)

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.tokens[hash]
	return exists
}

// Clear removes all tokens from the spent set.
// Called during epoch rotation.
func (s *SpentSet) Clear(newEpoch uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens = make(map[[32]byte]struct{})
	s.epoch = newEpoch
}

// Size returns the number of spent tokens.
func (s *SpentSet) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens)
}

// Epoch returns the current epoch of the spent set.
func (s *SpentSet) Epoch() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.epoch
}
