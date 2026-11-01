// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"errors"
	"sync/atomic"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/capture"
)

// IEC104Pressure is observational telemetry, separate from enforcement health.
// Totals last for the engine process lifetime, including configuration rebuilds.
type IEC104Pressure struct {
	InjectorFailures      uint64               `json:"injectorFailures"`
	HeldPackets           int                  `json:"heldPackets"`
	HeldBytes             int                  `json:"heldBytes"`
	OldestPendingSeconds  float64              `json:"oldestPendingSeconds"`
	ActiveSessions        int                  `json:"activeSessions"`
	TrackedSessions       int                  `json:"trackedSessions"`
	Limits                IEC104PressureLimits `json:"limits"`
	Aborts                map[string]uint64    `json:"aborts"`
	ResetWorkerRejections uint64               `json:"resetWorkerRejections"`
	VerdictFailures       uint64               `json:"verdictFailures"`
}

// IEC104PressureLimits describes fixed bounds, not configuration knobs.
type IEC104PressureLimits struct {
	HeldPackets           int     `json:"heldPackets"`
	HeldPacketsPerSession int     `json:"heldPacketsPerSession"`
	HeldBytesPerSession   int     `json:"heldBytesPerSession"`
	PendingSeconds        float64 `json:"pendingSeconds"`
	Sessions              int     `json:"sessions"`
	ResetWorkerJobs       int     `json:"resetWorkerJobs"`
}

var pressureTotals struct {
	worker   atomic.Uint64
	injector atomic.Uint64
	verdict  atomic.Uint64
}

func init() {
	for _, reason := range iecAbortReasons {
		metrics.IEC104AbortsTotal.WithLabelValues(reason.name).Add(0)
	}
}

func countIECAbort(reason *iecAbortReason) {
	reason.total.Add(1)
	metrics.IEC104AbortsTotal.WithLabelValues(reason.name).Inc()
}

func countIECVerdictFailure(err error) {
	// Closing a queue intentionally drops its tokens; it is not a failed verdict.
	if err != nil && !errors.Is(err, capture.ErrQueueClosed) && !errors.Is(err, capture.ErrTokenFlushed) {
		pressureTotals.verdict.Add(1)
		metrics.IEC104VerdictFailuresTotal.Inc()
	}
}

func (t *iecTable) pressure() IEC104Pressure {
	out := IEC104Pressure{InjectorFailures: pressureTotals.injector.Load(), Limits: IEC104PressureLimits{
		HeldPackets: iecMaxHeldGlobal, HeldPacketsPerSession: iecMaxHeldPerSession,
		HeldBytesPerSession: iecMaxHeldBytes, PendingSeconds: iecPendingTimeout.Seconds(),
		Sessions: iecMaxSessions, ResetWorkerJobs: blockWorkerQueue,
	}, Aborts: make(map[string]uint64, len(iecAbortReasons)),
		ResetWorkerRejections: pressureTotals.worker.Load(), VerdictFailures: pressureTotals.verdict.Load()}
	for _, reason := range iecAbortReasons {
		out.Aborts[reason.name] = reason.total.Load()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	out.TrackedSessions = len(t.sessions)
	for _, s := range t.sessions {
		if !t.pressureOffline && (s.state == iecSynSent || s.state == iecEstablished) {
			out.ActiveSessions++
		}
		// A tombstone can retain a replacement handshake, sharing its tuple slot.
		if !t.pressureOffline && s.next != nil {
			out.ActiveSessions++
		}
		out.HeldBytes += s.heldBytes
		out.HeldPackets += len(s.held)
		for _, h := range s.held {
			out.OldestPendingSeconds = max(out.OldestPendingSeconds, now.Sub(h.since).Seconds())
		}
	}
	return out
}

// IEC104Diagnostics snapshots the current configuration under the lifecycle
// lock, so a concurrent rebuild cannot return a retired table.
func (e *Engine) IEC104Diagnostics() IEC104Pressure {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.iec.pressure()
}

// IEC104PressureMetrics supplies an atomic scrape of current pressure.
func (e *Engine) IEC104PressureMetrics() map[string]float64 {
	p := e.IEC104Diagnostics()
	return map[string]float64{
		"held_packets": float64(p.HeldPackets), "held_bytes": float64(p.HeldBytes),
		"oldest_pending_seconds": p.OldestPendingSeconds, "sessions_active": float64(p.ActiveSessions),
		"sessions_tracked": float64(p.TrackedSessions), "sessions_limit": float64(p.Limits.Sessions),
		"held_packets_limit":             float64(p.Limits.HeldPackets),
		"held_packets_per_session_limit": float64(p.Limits.HeldPacketsPerSession),
		"held_bytes_per_session_limit":   float64(p.Limits.HeldBytesPerSession),
		"pending_seconds_limit":          p.Limits.PendingSeconds, "reset_worker_jobs_limit": float64(p.Limits.ResetWorkerJobs),
	}
}
