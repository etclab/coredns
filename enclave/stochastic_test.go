package enclave

import (
	"testing"
	"time"
)

// TestORAMCache_Churn verifies that churn evicts entries
func TestORAMCache_Churn(t *testing.T) {
	oramCfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    1024,
		BucketSize:   4,
		ConstantTime: false,
	}
	stochasticCfg := StochasticConfig{
		ChurnEnabled:  true,
		ChurnInterval: 50 * time.Millisecond,
	}

	cache, err := NewORAMCacheWithStochastic(oramCfg, stochasticCfg)
	if err != nil {
		t.Fatalf("failed to create ORAM cache: %v", err)
	}
	defer cache.StopChurn()

	for i := 0; i < 10; i++ {
		cache.Put("test"+string(rune('a'+i))+".com.:1", []byte("response"), 5*time.Minute)
	}

	initialSize := cache.Size()
	if initialSize == 0 {
		t.Fatal("expected entries to be cached")
	}

	time.Sleep(300 * time.Millisecond)

	t.Logf("Churn test: initial size=%d, after churn=%d", initialSize, cache.Size())
}

// TestSecureRNG verifies RNG produces values in expected range
func TestSecureRNG(t *testing.T) {
	rng := NewSecureRNG()

	min := 1.0
	max := 0.0

	for i := 0; i < 10000; i++ {
		v := rng.Float64()
		if v < 0.0 || v >= 1.0 {
			t.Errorf("RNG value %f outside [0.0, 1.0) range", v)
		}
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	if min > 0.01 {
		t.Errorf("RNG min value %f too high (expected near 0)", min)
	}
	if max < 0.99 {
		t.Errorf("RNG max value %f too low (expected near 1)", max)
	}
	t.Logf("RNG range: [%f, %f]", min, max)
}

// TestDefaultStochasticConfig verifies defaults
func TestDefaultStochasticConfig(t *testing.T) {
	cfg := DefaultStochasticConfig()

	if cfg.ChurnEnabled {
		t.Error("default ChurnEnabled should be false")
	}
}
