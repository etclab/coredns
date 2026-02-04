package codohtarget

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// SaltManager manages epoch-based salts for MLE key derivation.
// Each epoch has a unique 32-byte salt derived from secure random.
type SaltManager struct {
	epochDuration int64 // seconds

	mu           sync.RWMutex
	currentEpoch int64
	currentSalt  []byte // 32 bytes
	prevEpoch    int64  // E-1 for grace period
	prevSalt     []byte // 32 bytes
}

// SaltResponse is the JSON response from the salt endpoint.
type SaltResponse struct {
	Epoch   int64  `json:"epoch"`
	Salt    string `json:"salt"`    // base64url encoded
	Expires int64  `json:"expires"` // Unix timestamp
}

// NewSaltManager creates a new salt manager with the given epoch duration.
func NewSaltManager(epochDurationSecs int64) *SaltManager {
	sm := &SaltManager{
		epochDuration: epochDurationSecs,
	}

	// Initialize with current epoch
	sm.rotateIfNeeded()
	return sm
}

// GetCurrentSalt returns the current epoch, salt, and expiry time.
func (sm *SaltManager) GetCurrentSalt() (epoch int64, salt []byte, expires int64) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Check if rotation needed
	currentEpoch := time.Now().Unix() / sm.epochDuration
	if currentEpoch != sm.currentEpoch {
		sm.mu.RUnlock()
		sm.rotateIfNeeded()
		sm.mu.RLock()
	}

	expires = (sm.currentEpoch + 1) * sm.epochDuration
	saltCopy := make([]byte, len(sm.currentSalt))
	copy(saltCopy, sm.currentSalt)
	return sm.currentEpoch, saltCopy, expires
}

// GetSaltForEpoch returns the salt for a given epoch (current or previous).
// Returns nil, false if the epoch is not current or previous.
func (sm *SaltManager) GetSaltForEpoch(epoch int64) ([]byte, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if epoch == sm.currentEpoch {
		saltCopy := make([]byte, len(sm.currentSalt))
		copy(saltCopy, sm.currentSalt)
		return saltCopy, true
	}

	if epoch == sm.prevEpoch && sm.prevSalt != nil {
		saltCopy := make([]byte, len(sm.prevSalt))
		copy(saltCopy, sm.prevSalt)
		return saltCopy, true
	}

	return nil, false
}

// rotateIfNeeded checks if epoch has changed and rotates salts if needed.
func (sm *SaltManager) rotateIfNeeded() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	currentEpoch := time.Now().Unix() / sm.epochDuration

	if currentEpoch == sm.currentEpoch {
		return
	}

	// Rotate: current becomes previous
	if sm.currentSalt != nil {
		sm.prevEpoch = sm.currentEpoch
		sm.prevSalt = sm.currentSalt
	}

	// Generate new salt for current epoch
	sm.currentEpoch = currentEpoch
	sm.currentSalt = make([]byte, 32)
	if _, err := rand.Read(sm.currentSalt); err != nil {
		// This should never happen, but log it
		log.Errorf("Failed to generate salt: %v", err)
	}

	log.Infof("Salt rotated to epoch %d", currentEpoch)
}

// ServeHTTP handles GET requests for /.well-known/codoh-salt
func (sm *SaltManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	epoch, salt, expires := sm.GetCurrentSalt()

	resp := SaltResponse{
		Epoch:   epoch,
		Salt:    base64.RawURLEncoding.EncodeToString(salt),
		Expires: expires,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}
