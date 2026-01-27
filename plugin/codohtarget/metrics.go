package codohtarget

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	targetRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "codoh_target",
		Name:      "requests_total",
		Help:      "Total number of ODoH target requests.",
	}, []string{"status"})

	targetDecryptSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "codoh_target",
		Name:      "decrypt_seconds",
		Help:      "Time spent decrypting ODoH queries (HPKE).",
		Buckets:   prometheus.DefBuckets,
	})

	targetEncryptSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "codoh_target",
		Name:      "encrypt_seconds",
		Help:      "Time spent encrypting ODoH responses (HPKE).",
		Buckets:   prometheus.DefBuckets,
	})

	targetResolutionSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "codoh_target",
		Name:      "resolution_seconds",
		Help:      "Time spent resolving DNS queries upstream.",
		Buckets:   prometheus.DefBuckets,
	})

	targetLatencySeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "codoh_target",
		Name:      "latency_seconds",
		Help:      "Total end-to-end latency for ODoH target requests.",
		Buckets:   prometheus.DefBuckets,
	})

	// Token metrics
	tokensIssuedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "codoh_target",
		Name:      "tokens_issued_total",
		Help:      "Total number of VOPRF tokens issued.",
	}, []string{"status"}) // success, rate_limited, error

	tokensVerifiedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "codoh_target",
		Name:      "tokens_verified_total",
		Help:      "Total number of token verifications.",
	}, []string{"status"}) // valid, invalid, expired, error
)