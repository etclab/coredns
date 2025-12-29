package odohproxy

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	proxyRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "odoh_proxy",
		Name:      "requests_total",
		Help:      "Total number of ODoH proxy requests.",
	}, []string{"status"})

	proxyLatencySeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "odoh_proxy",
		Name:      "latency_seconds",
		Help:      "Proxy round-trip latency in seconds.",
		Buckets:   prometheus.DefBuckets,
	})
)