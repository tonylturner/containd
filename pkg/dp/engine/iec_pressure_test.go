// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/capture"
)

func assertNoIECHolds(t *testing.T, e *Engine) {
	t.Helper()
	p := e.IEC104Diagnostics()
	if p.HeldPackets != 0 || p.HeldBytes != 0 || p.OldestPendingSeconds != 0 {
		t.Fatalf("stale pressure: %+v", p)
	}
}

func TestIECPressureHoldReleasePaths(t *testing.T) {
	for _, path := range []string{"release", "deny", "timeout", "rst", "fin", "verdict", "queue", "policy", "rebuild"} {
		t.Run(path, func(t *testing.T) {
			h := newIECHarness(t, "enforce")
			h.handshake()
			cmd := iframe(46, 1)
			pkt, d := h.send(true, cmd[:4])
			if d.Action != capture.Hold {
				t.Fatal(d)
			}
			h.clock = h.clock.Add(500 * time.Millisecond)
			p := h.e.IEC104Diagnostics()
			if p.HeldPackets != 1 || p.HeldBytes != 4 || p.OldestPendingSeconds != .5 || p.ActiveSessions != 1 || p.TrackedSessions != 1 {
				t.Fatalf("pressure: %+v", p)
			}
			switch path {
			case "release":
				h.send(true, cmd[4:])
			case "deny":
				h.send(true, append(cmd[4:], iframe(45, 1)...))
			case "timeout":
				h.clock = h.clock.Add(iecPendingTimeout)
				h.e.iec.expire()
			case "rst":
				h.e.handlePacket(h.pkt(true, capture.TCPFlagRST, h.cSeq, h.sSeq, nil))
			case "fin":
				h.e.handlePacket(h.pkt(true, capture.TCPFlagFIN|capture.TCPFlagACK, h.cSeq, h.sSeq, nil))
			case "verdict":
				h.e.hooks.onVerdict(pkt.Token, capture.VerdictDrop, capture.ErrQueueClosed)
			case "queue":
				h.e.iec.onSourceDown()
			case "policy":
				h.policy.matched = false
				h.e.LoadRules(iecSnapshot("enforce"))
			case "rebuild":
				fresh, err := New(Config{ResetInjector: h.inj})
				if err != nil {
					t.Fatal(err)
				}
				h.e.Reconfigure(fresh)
			}
			assertNoIECHolds(t, h.e)
		})
	}
}

func TestIECPressureEveryAbortClearsGauges(t *testing.T) {
	for _, reason := range []string{abortDeny, abortTimeout, abortBound, abortStream, abortFraming, abortTransport, abortPolicy, abortQueue, abortMidstream, abortUnhealthy} {
		t.Run(reason, func(t *testing.T) {
			h := newIECHarness(t, "enforce")
			h.handshake()
			h.send(true, iframe(46, 1)[:4])
			before := h.e.IEC104Diagnostics().Aborts[reason]
			table := h.e.iec
			table.mu.Lock()
			for _, s := range table.sessions {
				table.abortLocked(s, reason, "", nil, h.clock)
			}
			table.mu.Unlock()
			assertNoIECHolds(t, h.e)
			if got := h.e.IEC104Diagnostics(); got.Aborts[reason] != before+1 || got.ActiveSessions != 0 {
				t.Fatalf("abort pressure: %+v", got)
			}
		})
	}
}

func TestIECPressureTotalsAndWorkerSaturation(t *testing.T) {
	h := newIECHarness(t, "enforce")
	before := h.e.IEC104Diagnostics()
	table := h.e.iec
	table.jobs = newWorker(1)
	table.jobs.submit(func() {})
	table.finish(iecActions{jobs: []func(){func() {}}})
	table.onVerdict(h.token(), errors.New("verdict failed"))
	table.onVerdict(h.token(), capture.ErrQueueClosed)
	after := h.e.IEC104Diagnostics()
	if after.ResetWorkerRejections != before.ResetWorkerRejections+1 || after.VerdictFailures != before.VerdictFailures+1 {
		t.Fatalf("totals before=%+v after=%+v", before, after)
	}
	fresh, err := New(Config{ResetInjector: h.inj})
	if err != nil {
		t.Fatal(err)
	}
	h.e.Reconfigure(fresh)
	if got := h.e.IEC104Diagnostics(); got.ResetWorkerRejections != after.ResetWorkerRejections || got.VerdictFailures != after.VerdictFailures {
		t.Fatalf("totals lost on rebuild: %+v", got)
	}
}

func TestIECPressureStopAndPrometheus(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	h.send(true, iframe(46, 1)[:4])
	metrics.SetIEC104PressureReader(h.e.IEC104PressureMetrics)
	assertMetric := func(name string, want float64) {
		t.Helper()
		families, err := prometheus.DefaultGatherer.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range families {
			if f.GetName() == "containd_dp_iec104_"+name {
				if len(f.Metric[0].Label) != 0 || f.Metric[0].GetGauge().GetValue() != want {
					t.Fatalf("metric: %v", f)
				}
				return
			}
		}
		t.Fatal("metric missing: " + name)
	}
	assertMetric("held_packets", 1)
	assertMetric("held_bytes", 4)
	h.e.iec.onSourceDown() // The capture stop/rebuild callback drops the ledger.
	stop, done := make(chan struct{}), make(chan struct{})
	close(stop)
	go func() { h.e.iec.run(stop); close(done) }()
	<-done
	assertNoIECHolds(t, h.e)
	if p := h.e.IEC104Diagnostics(); p.ActiveSessions != 0 {
		t.Fatal(p)
	}
	assertMetric("held_packets", 0)
	assertMetric("held_bytes", 0)
	assertMetric("oldest_pending_seconds", 0)
	assertMetric("sessions_active", 0)
}

func TestIECPressureInjectorFailures(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	before := h.e.IEC104Diagnostics()
	h.inj.SetError(errors.New("injection failed"))
	table := h.e.iec
	table.mu.Lock()
	var s *iecSession
	for _, live := range table.sessions {
		s = live
	}
	table.abortLocked(s, abortDeny, "", nil, h.clock)
	target := s.reset.targets[iecDirClient]
	table.mu.Unlock()
	table.sendReset(s, iecDirClient, target.r)
	if got := h.e.IEC104Diagnostics(); got.InjectorFailures != before.InjectorFailures+1 {
		t.Fatal(got)
	}

	unavailable := newIECHarness(t, "enforce")
	p := unavailable.e.IEC104Diagnostics()
	unavailable.e.iec.health.fault(faultInjector, "injector unavailable")
	d := unavailable.e.handlePacket(unavailable.pkt(true, capture.TCPFlagSYN, testClientISN, 0, nil))
	if d.Action != capture.Drop || unavailable.e.IEC104Diagnostics().Aborts["injector"] != p.Aborts["injector"]+1 {
		t.Fatal(d)
	}
}
