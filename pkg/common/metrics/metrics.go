// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "containd"

// Data plane counters.
var (
	PacketsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "dp",
		Name:      "packets_total",
		Help:      "Total packets processed by the engine.",
	})
	BytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "dp",
		Name:      "bytes_total",
		Help:      "Total bytes processed by the engine.",
	})
	DPIEventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "dp",
		Name:      "dpi_events_total",
		Help:      "Total DPI events generated.",
	})
	IDSAlertsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "dp",
		Name:      "ids_alerts_total",
		Help:      "Total IDS alerts fired.",
	})
	VerdictsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "dp",
		Name:      "verdicts_total",
		Help:      "Total verdicts by action.",
	}, []string{"action"})
	FlowsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "dp",
		Name:      "flows_active",
		Help:      "Number of currently active flows.",
	})
	RuleEvalDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "dp",
		Name:      "rule_eval_duration_seconds",
		Help:      "Time spent evaluating rules per packet.",
		Buckets:   prometheus.DefBuckets,
	})
)

// Control plane gauges.
var (
	RulesCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "cp",
		Name:      "rules_count",
		Help:      "Number of firewall rules in the running config.",
	})
	NFTablesApplyDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "cp",
		Name:      "nftables_apply_duration_seconds",
		Help:      "Time spent applying nftables rulesets.",
		Buckets:   prometheus.DefBuckets,
	})
)

// Service gauges.
var (
	ServicesRunning = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "services",
		Name:      "running",
		Help:      "Whether a managed service is running (1) or stopped (0).",
	}, []string{"service"})
)

// Cache metrics.
var (
	VerdictCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "engine",
		Name:      "verdict_cache_hits_total",
		Help:      "Total verdict cache hits.",
	})
	VerdictCacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "engine",
		Name:      "verdict_cache_misses_total",
		Help:      "Total verdict cache misses.",
	})
)

// GoroutinesActive tracks the number of active goroutines.
var GoroutinesActive = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: namespace,
	Subsystem: "runtime",
	Name:      "goroutines_active",
	Help:      "Number of active goroutines.",
})

// DecoderPacketsTotal counts packets processed per decoder protocol.
var DecoderPacketsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: namespace,
	Subsystem: "dpi",
	Name:      "decoder_packets_total",
	Help:      "Packets processed per decoder protocol.",
}, []string{"protocol"})

// IDSRulesLoaded tracks the number of IDS rules currently loaded.
var IDSRulesLoaded = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: namespace,
	Subsystem: "ids",
	Name:      "rules_loaded",
	Help:      "Number of IDS rules currently loaded.",
})
