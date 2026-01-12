// Package codohtarget implements VOPRF token issuance using P256-SHA256.
package codohtarget

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
)

const (
	// P256 compressed point size
	p256ElementSize = 33
)

// epochManager handles VOPRF key rotation and token operations.
type epochManager struct {
	suite         oprf.Suite
	masterSecret  []byte
	epochDuration time.Duration

	currentKey   *oprf.PrivateKey
	currentEpoch uint32
	server       *oprf.Server
	mu           sync.RWMutex
}

// newEpochManager creates a new epoch manager with the given master secret and duration.
func newEpochManager(masterSecret []byte, epochDuration time.Duration) (*epochManager, error) {
	e := &epochManager{
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
func (e *epochManager) currentEpochNumber() uint32 {
	return uint32(time.Now().Unix() / int64(e.epochDuration.Seconds()))
}

// rotateIfNeeded checks if epoch has changed and rotates keys if necessary.
func (e *epochManager) rotateIfNeeded() error {
	currentEpoch := e.currentEpochNumber()

	e.mu.RLock()
	needsRotation := currentEpoch != e.currentEpoch
	e.mu.RUnlock()

	if needsRotation {
		return e.rotateToEpoch(currentEpoch)
	}
	return nil
}

// rotateToEpoch derives a new key for the given epoch.
func (e *epochManager) rotateToEpoch(epoch uint32) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Derive epoch-specific seed from master secret
	seed := e.deriveEpochSeed(epoch)

	// Derive key using CIRCL's DeriveKey (base mode to match client)
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
func (e *epochManager) deriveEpochSeed(epoch uint32) []byte {
	h := sha256.New()
	h.Write(e.masterSecret)
	epochBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(epochBytes, epoch)
	h.Write(epochBytes)
	return h.Sum(nil)
}

// evaluateBatch performs VOPRF evaluation on multiple blinded inputs.
// Input format: count (1 byte) || blinded_elements (count * 33 bytes each)
// Output format: count (1 byte) || evaluated_elements (count * 33 bytes each)
func (e *epochManager) evaluateBatch(blindedInputs []byte) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(blindedInputs) < 1 {
		return nil, errors.New("empty input")
	}

	count := int(blindedInputs[0])
	expectedLen := 1 + count*p256ElementSize
	if len(blindedInputs) != expectedLen {
		return nil, errors.New("invalid input length")
	}

	// Get the group for P256
	g := group.P256

	// Deserialize blinded elements
	elements := make([]group.Element, count)
	for i := 0; i < count; i++ {
		start := 1 + i*p256ElementSize
		end := start + p256ElementSize
		elem := g.NewElement()
		if err := elem.UnmarshalBinary(blindedInputs[start:end]); err != nil {
			return nil, err
		}
		elements[i] = elem
	}

	// Create evaluation request and evaluate
	req := &oprf.EvaluationRequest{Elements: elements}
	eval, err := e.server.Evaluate(req)
	if err != nil {
		return nil, err
	}

	// Serialize evaluated elements
	result := make([]byte, 1+count*p256ElementSize)
	result[0] = byte(count)
	for i, elem := range eval.Elements {
		start := 1 + i*p256ElementSize
		data, err := elem.MarshalBinaryCompress()
		if err != nil {
			return nil, err
		}
		copy(result[start:], data)
	}

	return result, nil
}

// verify checks if a token (input + output) is valid for the current epoch.
func (e *epochManager) verify(input, output []byte) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	expected, err := e.server.FullEvaluate(input)
	if err != nil {
		return false
	}
	return bytes.Equal(expected, output)
}

// epoch returns the current epoch number.
func (e *epochManager) epoch() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.currentEpoch
}

// publicKey returns the current epoch's public key for clients.
func (e *epochManager) publicKey() *oprf.PublicKey {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.currentKey.Public()
}

// generateMasterSecret creates a random master secret.
func generateMasterSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}
