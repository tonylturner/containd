// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestIECMetadataBudgetAdmission(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor"} {
		t.Run(mode, func(t *testing.T) {
			h := newIECHarness(t, mode)
			r := limits.NewResources(limits.NewBudget(1), h.e.ledger)
			h.e.sessions.resources = r
			p := h.pkt(true, capture.TCPFlagSYN, testClientISN, 0, nil)
			d := h.e.handlePacket(p)
			want := capture.Drop
			if mode == "monitor" {
				want = capture.Repeat
			}
			if d.Action != want || len(h.e.sessions.sessions) != 0 || r.Budget.Status().InUse != 0 {
				t.Fatalf("metadata admission = %+v, sessions=%d budget=%+v", d, len(h.e.sessions.sessions), r.Budget.Status())
			}
			hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
			if len(hits) != 1 || hits[0].Mode != limits.Mode(mode) || hits[0].Total != 1 {
				t.Fatalf("metadata refusal = %+v", hits)
			}
			if len(h.inj.Resets()) != 0 || len(h.eventsOf("ics.decision")) != 0 {
				t.Fatal("refused admission created a reset or decision")
			}
			h.e.Close()
		})
	}
}

func TestIECFrameBudgetRefusalPrecedesPublication(t *testing.T) {
	h := newIECHarness(t, "enforce")
	r := limits.NewResources(limits.NewBudget(16384), h.e.ledger)
	h.e.sessions.resources = r
	h.handshake()
	blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 16384-r.Budget.Status().InUse-16)
	if !ok {
		t.Fatal("blocker")
	}
	_, d := h.send(true, iframe(46, 1))
	if d.Action != capture.Drop || d.Reason != "state_limit" || len(h.eventsOf("ics.decision")) != 0 {
		t.Fatalf("published a frame without retaining its range: %+v", d)
	}
	blocker.Release()
	h.e.Close()
	if r.Budget.Status().InUse != 0 {
		t.Fatal("session teardown leaked")
	}
}

func TestIECAckBudgetRefusalIsTerminal(t *testing.T) {
	h := newIECHarness(t, "enforce")
	r := limits.NewResources(limits.NewBudget(16384), h.e.ledger)
	h.e.sessions.resources = r
	h.handshake()
	h.send(true, iframe(46, 1))
	blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 16384-r.Budget.Status().InUse-7)
	if !ok {
		t.Fatal("blocker")
	}
	p := h.pkt(false, capture.TCPFlagACK, h.sSeq, h.clientISN+1+8, nil)
	d := h.e.handlePacket(p)
	if d.Action != capture.Drop || d.Reason != "state_limit" {
		t.Fatalf("ack copy refusal = %+v", d)
	}
	blocker.Release()
	if d = h.e.handlePacket(p); d.Action != capture.Drop {
		t.Fatal("ack-refused incarnation resumed")
	}
	h.e.Close()
	if r.Budget.Status().InUse != 0 {
		t.Fatal("session teardown leaked")
	}
}

func TestIECInspectionRetirementReleasesManagerBindings(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	h.send(true, iframe(46, 1))
	// Manager admission also reserves the independent directional-flow side
	// binding. Only Engine.Close owns retirement of that still-live flow.
	var flowCredit int64
	for _, s := range h.e.sessions.sessions {
		flowCredit = limits.BindingMetadataBytes + int64(2*len(s.flow.ID()))
	}
	h.e.sessions.stopInspection()
	if got := h.e.budget.Status().InUse; got != flowCredit {
		t.Fatalf("retired session retained %d inspection bytes, want independent flow credit %d", got, flowCredit)
	}
	h.e.Close()
	if got := h.e.budget.Status().InUse; got != 0 {
		t.Fatalf("engine teardown retained %d inspection bytes", got)
	}
}

func TestIECMonitorFrameBudgetRefusalIsTerminal(t *testing.T) {
	h := newIECHarness(t, "monitor")
	r := limits.NewResources(limits.NewBudget(16384), h.e.ledger)
	h.e.sessions.resources = r
	h.handshake()
	// A monitor allocation may use only three quarters of the total.
	blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 12288-r.Budget.Status().InUse-16)
	if !ok {
		t.Fatal("blocker")
	}
	_, d := h.send(true, iframe(46, 1))
	if d.Action != capture.Repeat || len(h.eventsOf("ics.decision")) != 0 {
		t.Fatalf("monitor frame refusal = %+v", d)
	}
	blocker.Release()
	before := r.Budget.Status().InUse
	h.send(true, iframe(46, 2))
	if r.Budget.Status().InUse != before || len(h.eventsOf("ics.decision")) != 0 {
		t.Fatal("monitor parsing resumed after pressure subsided")
	}
	hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Mode != limits.ModeMonitor || hits[0].Total != 1 {
		t.Fatalf("monitor refusal transitions = %+v", hits)
	}
	h.e.Close()
	if r.Budget.Status().InUse != 0 {
		t.Fatal("monitor teardown leaked")
	}
}
