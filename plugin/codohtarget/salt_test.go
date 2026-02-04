package codohtarget

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewSaltManager(t *testing.T) {
	sm := NewSaltManager(3600) // 1 hour epochs

	epoch, salt, expires := sm.GetCurrentSalt()

	if epoch <= 0 {
		t.Errorf("Expected positive epoch, got %d", epoch)
	}
	if len(salt) != 32 {
		t.Errorf("Expected 32-byte salt, got %d bytes", len(salt))
	}
	if expires <= time.Now().Unix() {
		t.Errorf("Expected future expiry, got %d", expires)
	}
}

func TestSaltManagerEpochRotation(t *testing.T) {
	// Use very short epoch for testing
	sm := NewSaltManager(1) // 1 second epochs

	epoch1, salt1, _ := sm.GetCurrentSalt()

	// Wait for epoch rotation
	time.Sleep(1100 * time.Millisecond)

	epoch2, salt2, _ := sm.GetCurrentSalt()

	if epoch2 <= epoch1 {
		t.Errorf("Expected epoch to advance from %d, got %d", epoch1, epoch2)
	}

	// Salts should be different
	if string(salt1) == string(salt2) {
		t.Error("Expected different salts after rotation")
	}
}

func TestSaltManagerGracePeriod(t *testing.T) {
	// Use short epoch for testing
	sm := NewSaltManager(1) // 1 second epochs

	// Get current salt
	epoch1, salt1, _ := sm.GetCurrentSalt()

	// Wait for rotation
	time.Sleep(1100 * time.Millisecond)

	// Should still be able to get previous epoch's salt
	prevSalt, ok := sm.GetSaltForEpoch(epoch1)
	if !ok {
		t.Error("Expected to get previous epoch's salt")
	}
	if string(prevSalt) != string(salt1) {
		t.Error("Previous epoch salt mismatch")
	}

	// Current epoch should be different
	epoch2, _, _ := sm.GetCurrentSalt()
	if epoch2 == epoch1 {
		t.Error("Expected different current epoch after rotation")
	}
}

func TestSaltManagerGetSaltForInvalidEpoch(t *testing.T) {
	sm := NewSaltManager(3600)

	// Try to get salt for invalid epoch
	_, ok := sm.GetSaltForEpoch(0)
	if ok {
		t.Error("Expected failure for epoch 0")
	}

	_, ok = sm.GetSaltForEpoch(999999999999)
	if ok {
		t.Error("Expected failure for future epoch")
	}
}

func TestSaltManagerHTTPHandler(t *testing.T) {
	sm := NewSaltManager(3600)

	// Test GET request
	req := httptest.NewRequest(http.MethodGet, "/.well-known/codoh-salt", nil)
	w := httptest.NewRecorder()

	sm.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Parse response
	var resp SaltResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Epoch <= 0 {
		t.Errorf("Expected positive epoch, got %d", resp.Epoch)
	}
	if resp.Salt == "" {
		t.Error("Expected non-empty salt")
	}
	if resp.Expires <= time.Now().Unix() {
		t.Errorf("Expected future expiry, got %d", resp.Expires)
	}

	// Test POST request (should fail)
	req = httptest.NewRequest(http.MethodPost, "/.well-known/codoh-salt", nil)
	w = httptest.NewRecorder()

	sm.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for POST, got %d", w.Code)
	}
}

func TestSaltManagerConsistency(t *testing.T) {
	sm := NewSaltManager(3600)

	// Multiple calls should return same values within same epoch
	epoch1, salt1, exp1 := sm.GetCurrentSalt()
	epoch2, salt2, exp2 := sm.GetCurrentSalt()

	if epoch1 != epoch2 {
		t.Error("Epoch changed between calls")
	}
	if string(salt1) != string(salt2) {
		t.Error("Salt changed between calls")
	}
	if exp1 != exp2 {
		t.Error("Expiry changed between calls")
	}
}
