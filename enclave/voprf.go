package enclave

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/cloudflare/circl/oprf"
)

// EpochManager handles VOPRF key derivation and token verification.
// Mirrors the target's epochManager but only verifies (no issuance).
type EpochManager struct {
	suite         oprf.Suite
	masterSecret  []byte
	epochDuration time.Duration

	currentKey   *oprf.PrivateKey
	currentEpoch uint32
	server       *oprf.Server
	mu           sync.RWMutex
}

// NewEpochManager creates a new epoch manager for token verification.
func NewEpochManager(masterSecret []byte, epochDuration time.Duration) (*EpochManager, error) {
	e := &EpochManager{
		suite:         oprf.SuiteP256,
		masterSecret:  masterSecret,
		epochDuration: epochDuration,
	}

	// Initialize with current epoch
	if err := e.rotateToEpoch(e.currentEpochNumber()); err != nil {
		return nil, err
	}

	return e, nil
}

// currentEpochNumber returns the current epoch based on time.
func (e *EpochManager) currentEpochNumber() uint32 {
	return uint32(time.Now().Unix() / int64(e.epochDuration.Seconds()))
}

// RotateIfNeeded checks if epoch has changed and rotates keys if necessary.
// Returns true if rotation occurred.
func (e *EpochManager) RotateIfNeeded() (bool, error) {
	currentEpoch := e.currentEpochNumber()

	e.mu.RLock()
	needsRotation := currentEpoch != e.currentEpoch
	e.mu.RUnlock()

	if needsRotation {
		return true, e.rotateToEpoch(currentEpoch)
	}
	return false, nil
}

// rotateToEpoch derives a new key for the given epoch.
func (e *EpochManager) rotateToEpoch(epoch uint32) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Derive epoch-specific seed from master secret
	seed := e.deriveEpochSeed(epoch)

	// Derive key using CIRCL's DeriveKey (base mode to match target)
	key, err := oprf.DeriveKey(e.suite, oprf.BaseMode, seed, []byte("odoh-voprf-epoch-key"))
	if err != nil {
		return err
	}

	e.currentKey = key
	e.currentEpoch = epoch
	srv := oprf.NewServer(e.suite, key)
	e.server = &srv

	return nil
}

// deriveEpochSeed creates a deterministic seed for the given epoch.
func (e *EpochManager) deriveEpochSeed(epoch uint32) []byte {
	h := sha256.New()
	h.Write(e.masterSecret)
	epochBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(epochBytes, epoch)
	h.Write(epochBytes)
	return h.Sum(nil)
}

// Verify checks if a token (input + output) is valid for the given epoch.
// Returns true if valid, false otherwise.
func (e *EpochManager) Verify(epoch uint32, input, output []byte) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Check if epoch matches current
	if epoch != e.currentEpoch {
		return false
	}

	// Recompute OPRF output and compare
	expected, err := e.server.FullEvaluate(input)
	if err != nil {
		return false
	}
	return bytes.Equal(expected, output)
}

// CurrentEpoch returns the current epoch number.
func (e *EpochManager) CurrentEpoch() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.currentEpoch
}

// EpochEnd returns the time when the current epoch ends.
func (e *EpochManager) EpochEnd() time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	epochStart := int64(e.currentEpoch) * int64(e.epochDuration.Seconds())
	epochEnd := epochStart + int64(e.epochDuration.Seconds())
	return time.Unix(epochEnd, 0)
}
