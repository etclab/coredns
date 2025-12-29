package odohtarget

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	targetRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "odoh_target",
		Name:      "requests_total",
		Help:      "Total number of ODoH target requests.",
	}, []string{"status"})

	targetDecryptSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "odoh_target",
		Name:      "decrypt_seconds",
		Help:      "Time spent decrypting ODoH queries (HPKE).",
		Buckets:   prometheus.DefBuckets,
	})

	targetEncryptSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "odoh_target",
		Name:      "encrypt_seconds",
		Help:      "Time spent encrypting ODoH responses (HPKE).",
		Buckets:   prometheus.DefBuckets,
	})

	targetResolutionSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "odoh_target",
		Name:      "resolution_seconds",
		Help:      "Time spent resolving DNS queries upstream.",
		Buckets:   prometheus.DefBuckets,
	})

	targetLatencySeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "odoh_target",
		Name:      "latency_seconds",
		Help:      "Total end-to-end latency for ODoH target requests.",
		Buckets:   prometheus.DefBuckets,
	})
)