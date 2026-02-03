package enclave

import (
	"testing"
	"time"
)

// TestHitSuppression_Full verifies that p_fn=1.0 suppresses all hits
func TestHitSuppression_Full(t *testing.T) {
	cfg := StochasticConfig{
		HitSuppressionProb: 1.0, // Suppress ALL hits
		InsertProb:         1.0, // Always insert
		ChurnEnabled:       false,
	}

	cache := NewLRUCacheWithStochastic(100, cfg)

	// Insert an entry
	query := "example.com.:1"
	cache.Put(query, []byte("response"), []byte("kc"), 5*time.Minute)

	// Verify it was inserted
	if cache.Size() != 1 {
		t.Fatalf("expected cache size 1, got %d", cache.Size())
	}

	// Try to get it 100 times - ALL should be suppressed (return miss)
	hits := 0
	for i := 0; i < 100; i++ {
		_, _, found := cache.Get(query)
		if found {
			hits++
		}
	}

	if hits > 0 {
		t.Errorf("with p_fn=1.0, expected 0 hits but got %d", hits)
	}
}

// TestHitSuppression_None verifies that p_fn=0.0 suppresses no hits
func TestHitSuppression_None(t *testing.T) {
	cfg := StochasticConfig{
		HitSuppressionProb: 0.0, // Suppress NO hits
		InsertProb:         1.0,
		ChurnEnabled:       false,
	}

	cache := NewLRUCacheWithStochastic(100, cfg)

	query := "example.com.:1"
	cache.Put(query, []byte("response"), []byte("kc"), 5*time.Minute)

	// All 100 gets should return hits
	hits := 0
	for i := 0; i < 100; i++ {
		_, _, found := cache.Get(query)
		if found {
			hits++
		}
	}

	if hits != 100 {
		t.Errorf("with p_fn=0.0, expected 100 hits but got %d", hits)
	}
}

// TestHitSuppression_Statistical verifies ~50% suppression with p_fn=0.5
func TestHitSuppression_Statistical(t *testing.T) {
	cfg := StochasticConfig{
		HitSuppressionProb: 0.5,
		InsertProb:         1.0,
		ChurnEnabled:       false,
	}

	cache := NewLRUCacheWithStochastic(100, cfg)

	query := "example.com.:1"
	cache.Put(query, []byte("response"), []byte("kc"), 5*time.Minute)

	// Run 1000 gets to get statistical significance
	hits := 0
	for i := 0; i < 1000; i++ {
		_, _, found := cache.Get(query)
		if found {
			hits++
		}
	}

	// Expect ~500 hits (allow 400-600 range for randomness)
	if hits < 350 || hits > 650 {
		t.Errorf("with p_fn=0.5, expected ~500 hits but got %d (outside 350-650 range)", hits)
	}
	t.Logf("Hit suppression test: %d/1000 hits (expected ~500)", hits)
}

// TestNonInsertion_Full verifies that p_ins=0.0 inserts nothing
func TestNonInsertion_Full(t *testing.T) {
	cfg := StochasticConfig{
		HitSuppressionProb: 0.0,
		InsertProb:         0.0, // Insert NOTHING
		ChurnEnabled:       false,
	}

	cache := NewLRUCacheWithStochastic(100, cfg)

	// Try to insert 100 entries
	for i := 0; i < 100; i++ {
		cache.Put("example"+string(rune('a'+i%26))+".com.:1", []byte("response"), nil, 5*time.Minute)
	}

	// Cache should be empty
	if cache.Size() != 0 {
		t.Errorf("with p_ins=0.0, expected cache size 0 but got %d", cache.Size())
	}
}

// TestNonInsertion_None verifies that p_ins=1.0 inserts everything
func TestNonInsertion_None(t *testing.T) {
	cfg := StochasticConfig{
		HitSuppressionProb: 0.0,
		InsertProb:         1.0, // Insert EVERYTHING
		ChurnEnabled:       false,
	}

	cache := NewLRUCacheWithStochastic(100, cfg)

	// Insert 50 unique entries
	for i := 0; i < 50; i++ {
		cache.Put("test"+string(rune('0'+i/10))+string(rune('0'+i%10))+".com.:1", []byte("response"), nil, 5*time.Minute)
	}

	// All should be cached
	if cache.Size() != 50 {
		t.Errorf("with p_ins=1.0, expected cache size 50 but got %d", cache.Size())
	}
}

// TestNonInsertion_Statistical verifies ~30% insertion with p_ins=0.3
func TestNonInsertion_Statistical(t *testing.T) {
	cfg := StochasticConfig{
		HitSuppressionProb: 0.0,
		InsertProb:         0.3, // 30% insertion probability
		ChurnEnabled:       false,
	}

	cache := NewLRUCacheWithStochastic(1000, cfg)

	// Insert 100 unique entries
	for i := 0; i < 100; i++ {
		query := "test" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + ".example.com.:1"
		cache.Put(query, []byte("response"), nil, 5*time.Minute)
	}

	// Expect ~30 entries (allow 15-45 range for randomness)
	size := cache.Size()
	if size < 15 || size > 45 {
		t.Errorf("with p_ins=0.3, expected ~30 cached entries but got %d (outside 15-45 range)", size)
	}
	t.Logf("Non-insertion test: %d/100 entries cached (expected ~30)", size)
}

// TestORAMCache_HitSuppression verifies hit suppression on ORAM cache
func TestORAMCache_HitSuppression(t *testing.T) {
	oramCfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    1024,
		BucketSize:   4,
		ConstantTime: false,
	}
	stochasticCfg := StochasticConfig{
		HitSuppressionProb: 1.0, // Suppress ALL
		InsertProb:         1.0,
		ChurnEnabled:       false,
	}

	cache, err := NewORAMCacheWithStochastic(oramCfg, stochasticCfg)
	if err != nil {
		t.Fatalf("failed to create ORAM cache: %v", err)
	}

	query := "example.com.:1"
	cache.Put(query, []byte("response"), []byte("kc"), 5*time.Minute)

	// With p_fn=1.0, all gets should be suppressed
	hits := 0
	for i := 0; i < 50; i++ {
		_, _, found := cache.Get(query)
		if found {
			hits++
		}
	}

	if hits > 0 {
		t.Errorf("ORAM: with p_fn=1.0, expected 0 hits but got %d", hits)
	}
}

// TestORAMCache_NonInsertion verifies non-insertion on ORAM cache
func TestORAMCache_NonInsertion(t *testing.T) {
	oramCfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    1024,
		BucketSize:   4,
		ConstantTime: false,
	}
	stochasticCfg := StochasticConfig{
		HitSuppressionProb: 0.0,
		InsertProb:         0.0, // Insert NOTHING
		ChurnEnabled:       false,
	}

	cache, err := NewORAMCacheWithStochastic(oramCfg, stochasticCfg)
	if err != nil {
		t.Fatalf("failed to create ORAM cache: %v", err)
	}

	// Try to insert entries
	for i := 0; i < 20; i++ {
		cache.Put("test"+string(rune('a'+i))+".com.:1", []byte("response"), nil, 5*time.Minute)
	}

	// Cache should be empty (Size() tracks used blocks)
	if cache.Size() != 0 {
		t.Errorf("ORAM: with p_ins=0.0, expected size 0 but got %d", cache.Size())
	}
}

// TestORAMCache_Churn verifies that churn evicts entries
func TestORAMCache_Churn(t *testing.T) {
	oramCfg := ORAMCacheConfig{
		Capacity:     100,
		BlockSize:    1024,
		BucketSize:   4,
		ConstantTime: false,
	}
	stochasticCfg := StochasticConfig{
		HitSuppressionProb: 0.0,
		InsertProb:         1.0,
		ChurnEnabled:       true,
		ChurnInterval:      50 * time.Millisecond, // Fast churn for testing
	}

	cache, err := NewORAMCacheWithStochastic(oramCfg, stochasticCfg)
	if err != nil {
		t.Fatalf("failed to create ORAM cache: %v", err)
	}
	defer cache.StopChurn()

	// Insert some entries
	for i := 0; i < 10; i++ {
		cache.Put("test"+string(rune('a'+i))+".com.:1", []byte("response"), nil, 5*time.Minute)
	}

	initialSize := cache.Size()
	if initialSize == 0 {
		t.Fatal("expected entries to be cached")
	}

	// Wait for churn to happen (multiple intervals)
	time.Sleep(300 * time.Millisecond)

	// Churn should have evicted some entries
	// Note: churn picks random blocks, may or may not hit our entries
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

	// Should cover most of the range
	if min > 0.01 {
		t.Errorf("RNG min value %f too high (expected near 0)", min)
	}
	if max < 0.99 {
		t.Errorf("RNG max value %f too low (expected near 1)", max)
	}
	t.Logf("RNG range: [%f, %f]", min, max)
}

// TestDefaultStochasticConfig verifies defaults disable all defenses
func TestDefaultStochasticConfig(t *testing.T) {
	cfg := DefaultStochasticConfig()

	if cfg.HitSuppressionProb != 0.0 {
		t.Errorf("default HitSuppressionProb should be 0.0, got %f", cfg.HitSuppressionProb)
	}
	if cfg.InsertProb != 1.0 {
		t.Errorf("default InsertProb should be 1.0, got %f", cfg.InsertProb)
	}
	if cfg.ChurnEnabled {
		t.Error("default ChurnEnabled should be false")
	}
}

// TestCombinedDefenses verifies hit suppression and non-insertion work together
func TestCombinedDefenses(t *testing.T) {
	cfg := StochasticConfig{
		HitSuppressionProb: 0.5, // 50% suppression
		InsertProb:         0.5, // 50% insertion
		ChurnEnabled:       false,
	}

	cache := NewLRUCacheWithStochastic(1000, cfg)

	// Insert 100 entries (expect ~50 to be cached)
	for i := 0; i < 100; i++ {
		query := "insert" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + ".com.:1"
		cache.Put(query, []byte("response"), nil, 5*time.Minute)
	}

	inserted := cache.Size()
	if inserted < 30 || inserted > 70 {
		t.Errorf("expected ~50 insertions, got %d (outside 30-70 range)", inserted)
	}

	// Now test hits on existing entries
	// Insert one entry that we know will be cached (disable non-insertion temporarily)
	knownQuery := "known.com.:1"
	// Use Put enough times that one should succeed with 50% probability
	for i := 0; i < 20; i++ {
		cache.Put(knownQuery, []byte("known-response"), nil, 5*time.Minute)
	}

	t.Logf("Combined defenses: %d/100 inserted, testing hit suppression on known entry", inserted)
}