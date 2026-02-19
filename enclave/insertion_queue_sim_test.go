package enclave

import (
	"math/rand"
	"testing"
)

// Simulation tests for queue dynamics using deterministic math/rand.
// These do NOT instantiate real handlers or caches — they model the
// probabilistic behavior of the batching system mathematically.

type simConfig struct {
	batchSize       int
	batchCommitProb float64
	missRate        float64 // fraction of queries that are misses (enqueue)
	maxQueueSize    int     // head-drop cap (0 = unbounded)
}

func runUniformSim(rng *rand.Rand, cfg simConfig, numQueries int) (maxDepth int) {
	queueDepth := 0

	for i := 0; i < numQueries; i++ {
		// Arrival: miss → enqueue (with head-drop if at capacity)
		if rng.Float64() < cfg.missRate {
			queueDepth++
			if cfg.maxQueueSize > 0 && queueDepth > cfg.maxQueueSize {
				queueDepth = cfg.maxQueueSize // head-drop
			}
		}

		// Commit: coin flip per query
		if rng.Float64() < cfg.batchCommitProb {
			drain := cfg.batchSize
			if drain > queueDepth {
				drain = queueDepth
			}
			queueDepth -= drain
		}

		if queueDepth > maxDepth {
			maxDepth = queueDepth
		}
	}
	return maxDepth
}

func TestSimUniform100QPS(t *testing.T) {
	configs := []simConfig{
		{batchSize: 10, batchCommitProb: 0.1, missRate: 0.5, maxQueueSize: 1000},
		{batchSize: 20, batchCommitProb: 0.05, missRate: 0.5, maxQueueSize: 1000},
		{batchSize: 5, batchCommitProb: 0.2, missRate: 0.5, maxQueueSize: 1000},
	}

	for _, cfg := range configs {
		rng := rand.New(rand.NewSource(42))
		maxDepth := runUniformSim(rng, cfg, 1000)

		// Steady-state expectation: BatchSize / BatchCommitProb
		steadyState := float64(cfg.batchSize) / cfg.batchCommitProb
		bound := int(2 * steadyState)

		if maxDepth > bound {
			t.Errorf("config (batch=%d, prob=%.2f): max_depth=%d > 2×steady_state=%d",
				cfg.batchSize, cfg.batchCommitProb, maxDepth, bound)
		} else {
			t.Logf("config (batch=%d, prob=%.2f): max_depth=%d, bound=%d ✓",
				cfg.batchSize, cfg.batchCommitProb, maxDepth, bound)
		}
	}
}

func TestSimBurstyTraffic(t *testing.T) {
	configs := []simConfig{
		{batchSize: 10, batchCommitProb: 0.1, missRate: 0.5, maxQueueSize: 1000},
		{batchSize: 20, batchCommitProb: 0.05, missRate: 0.5, maxQueueSize: 1000},
		{batchSize: 5, batchCommitProb: 0.2, missRate: 0.5, maxQueueSize: 1000},
	}

	for _, cfg := range configs {
		rng := rand.New(rand.NewSource(42))
		queueDepth := 0
		maxDepth := 0

		// Phase 1: Burst — 100 queries with 100% miss rate (all enqueue)
		for i := 0; i < 100; i++ {
			queueDepth++
			if cfg.maxQueueSize > 0 && queueDepth > cfg.maxQueueSize {
				queueDepth = cfg.maxQueueSize // head-drop
			}
			if rng.Float64() < cfg.batchCommitProb {
				drain := cfg.batchSize
				if drain > queueDepth {
					drain = queueDepth
				}
				queueDepth -= drain
			}
			if queueDepth > maxDepth {
				maxDepth = queueDepth
			}
		}

		burstPeakDepth := queueDepth

		// Phase 2: Uniform — 900 queries at normal miss rate
		recoveredByQuery := -1
		steadyState := float64(cfg.batchSize) / cfg.batchCommitProb
		for i := 0; i < 900; i++ {
			if rng.Float64() < cfg.missRate {
				queueDepth++
				if cfg.maxQueueSize > 0 && queueDepth > cfg.maxQueueSize {
					queueDepth = cfg.maxQueueSize // head-drop
				}
			}
			if rng.Float64() < cfg.batchCommitProb {
				drain := cfg.batchSize
				if drain > queueDepth {
					drain = queueDepth
				}
				queueDepth -= drain
			}
			if queueDepth > maxDepth {
				maxDepth = queueDepth
			}
			if recoveredByQuery < 0 && float64(queueDepth) <= 1.5*steadyState {
				recoveredByQuery = i
			}
		}

		// Assert: max queue depth ≤ 3× steady-state (looser bound for burst)
		bound := int(3 * steadyState)
		if maxDepth > bound {
			t.Errorf("config (batch=%d, prob=%.2f): max_depth=%d > 3×steady_state=%d",
				cfg.batchSize, cfg.batchCommitProb, maxDepth, bound)
		}

		// Assert: queue depth recovers within 200 queries after burst
		if recoveredByQuery < 0 || recoveredByQuery > 200 {
			t.Errorf("config (batch=%d, prob=%.2f): recovery at query %d (want ≤200), burst_peak=%d",
				cfg.batchSize, cfg.batchCommitProb, recoveredByQuery, burstPeakDepth)
		} else {
			t.Logf("config (batch=%d, prob=%.2f): max_depth=%d, bound=%d, recovery=%d ✓",
				cfg.batchSize, cfg.batchCommitProb, maxDepth, bound, recoveredByQuery)
		}
	}
}
