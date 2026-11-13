// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"sync/atomic"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/evidence"
)

func TestInspectionBudgetRefusalDisposition(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor"} {
		t.Run(mode, func(t *testing.T) {
			f := newModeFlow(t, mode, 502)
			f.syn()
			var losses atomic.Int32
			f.e.SetLearnLossHook(func(evidence.CollectionLoss) { losses.Add(1) })
			budget := f.e.budget
			before := budget.Status()
			blocker, ok := budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, before.Limit-before.InUse)
			if !ok {
				t.Fatal("blocker")
			}
			packet := modbusADU(1, 3, 0, 2)
			d := f.decide(1, capture.TCPFlagACK|capture.TCPFlagPSH, packet)
			want := capture.Drop
			if mode == "monitor" {
				want = capture.Repeat
			}
			if d.Action != want || mode == "enforce" && d.Reason != "state_limit" {
				t.Fatalf("refusal = %+v", d)
			}
			blocker.Release()
			for range 3 {
				if d = f.decide(1, capture.TCPFlagACK|capture.TCPFlagPSH, packet); d.Action != want {
					t.Fatalf("terminal incarnation resumed: %+v", d)
				}
			}
			hits := f.e.ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
			if len(hits) != 1 || hits[0].Mode != limits.Mode(mode) || hits[0].Total != 1 {
				t.Fatalf("refusal transitions: %+v", hits)
			}
			if mode == "monitor" && losses.Load() != 1 {
				t.Fatalf("learner loss count = %d", losses.Load())
			}
			for _, ev := range f.e.Events().List(0) {
				if ev.Proto == "modbus" && ev.Kind == "request" {
					t.Fatal("refused inspection published a request")
				}
			}
			select {
			case call := <-f.up.calls:
				t.Fatalf("state limit installed a kernel block: %s", call)
			default:
			}
			f.e.Close()
			if budget.Status().InUse != 0 {
				t.Fatalf("shutdown leaked credit: %+v", budget.Status())
			}
		})
	}
}

func TestIECInspectionBudgetRefusalDisposition(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor"} {
		t.Run(mode, func(t *testing.T) {
			h := newIECHarness(t, mode)
			h.handshake()
			var losses atomic.Int32
			h.e.SetLearnLossHook(func(evidence.CollectionLoss) { losses.Add(1) })
			budget := h.e.budget
			blocker, ok := budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, budget.Status().Limit)
			if !ok {
				t.Fatal("blocker")
			}
			_, d := h.send(true, iframe(46, 1))
			want := capture.Drop
			if mode == "monitor" {
				want = capture.Repeat
			}
			if d.Action != want || mode == "enforce" && d.Reason != "state_limit" {
				t.Fatalf("IEC refusal = %+v", d)
			}
			blocker.Release()
			if _, d = h.send(true, iframe(46, 1)); d.Action != want {
				t.Fatalf("IEC incarnation resumed after refusal: %+v", d)
			}
			hits := h.e.ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
			if len(hits) != 1 || hits[0].Mode != limits.Mode(mode) || hits[0].Total != 1 {
				t.Fatalf("IEC refusal transitions: %+v", hits)
			}
			if losses.Load() != 1 || len(h.eventsOf("ics.decision")) != 0 {
				t.Fatalf("lost IEC inspection was published: losses=%d decisions=%+v", losses.Load(), h.eventsOf("ics.decision"))
			}
			if mode == "enforce" {
				found := false
				for _, ev := range h.eventsOf("ics.session") {
					if ev.Attributes["outcome"] == "aborted" && ev.Attributes["reason"] == "bound" {
						found = true
					}
				}
				if !found {
					t.Fatal("budget exhaustion did not use the bound abort")
				}
			}
			if budget.Status().InUse != 0 {
				t.Fatal("IEC refused admission retained stream credit")
			}
		})
	}
}
