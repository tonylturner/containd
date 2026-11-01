// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package metrics

import (
	"sync/atomic"

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
	DPICoverageLosses = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "dpi",
		Name:      "coverage_losses_total",
		Help:      "Connection incarnations whose passive decoding stopped after transport observation loss.",
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
		Help:      "Observed managed service state: running (1), stopped (0); unknown states are omitted. The vpn aggregate is omitted unless a VPN is observed running or all VPNs are observed stopped.",
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

// IEC104 counters contain only fixed reason labels, never session identities.
var (
	IEC104AbortsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "dp_iec104", Name: "aborts_total",
		Help: "IEC104 aborts and fail-closed session admission rejections by reason.",
	}, []string{"reason"})
	IEC104InjectorFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "dp_iec104", Name: "injector_failures_total", Help: "Failed IEC104 TCP reset injection attempts.",
	})
	IEC104ResetWorkerRejectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "dp_iec104", Name: "reset_worker_rejections_total",
		Help: "IEC104 reset jobs rejected by the bounded worker.",
	})
	IEC104VerdictFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "dp_iec104", Name: "verdict_failures_total",
		Help: "Inline verdict submission or completion failures affecting IEC104 enforcement, excluding queue closure.",
	})
)

// iec104PressureReader follows the live engine across configuration rebuilds.
var iec104PressureReader atomic.Pointer[func() map[string]float64]

// SetIEC104PressureReader binds the process-wide exporter without registering
// collectors again. Combined-mode engine and management listeners share it.
func SetIEC104PressureReader(read func() map[string]float64) {
	iec104PressureReader.Store(&read)
}

type iec104PressureCollector struct{}

func (iec104PressureCollector) Describe(ch chan<- *prometheus.Desc) {
	for name, help := range iec104GaugeHelp {
		ch <- prometheus.NewDesc("containd_dp_iec104_"+name, help, nil, nil)
	}
}

func (iec104PressureCollector) Collect(ch chan<- prometheus.Metric) {
	values := map[string]float64{}
	if read := iec104PressureReader.Load(); read != nil {
		values = (*read)()
	}
	for name, help := range iec104GaugeHelp {
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("containd_dp_iec104_"+name, help, nil, nil), prometheus.GaugeValue, values[name])
	}
}

var iec104GaugeHelp = map[string]string{
	"held_packets":                   "Packets pending IEC104 framing and decision.",
	"held_bytes":                     "Payload bytes in held packets (including retransmissions).",
	"oldest_pending_seconds":         "Age of the oldest held IEC104 packet, zero when empty.",
	"sessions_active":                "Live IEC104 session incarnations, including replacement handshakes.",
	"sessions_tracked":               "IEC104 tuple slots including closed sessions and tombstones.",
	"sessions_limit":                 "Fixed IEC104 tuple slot cap.",
	"held_packets_limit":             "Fixed global IEC104 held packet cap.",
	"held_packets_per_session_limit": "Fixed IEC104 held packet cap per session.",
	"held_bytes_per_session_limit":   "Fixed IEC104 held payload byte cap per session.",
	"pending_seconds_limit":          "Fixed IEC104 pending packet timeout in seconds.",
	"reset_worker_jobs_limit":        "Fixed shared reset and block worker queue capacity.",
}

// Register once per process, including when both listeners run in combined mode.
func init() { prometheus.MustRegister(iec104PressureCollector{}) }
