// SPDX-License-Identifier: Apache-2.0
package dpi

import (
	"errors"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestManagerBudgetAdmissionHasNoFailureMarker(t *testing.T) {
	m, _, st := framedFixture()
	r := limits.NewResources(limits.NewBudget(4096), nil)
	m.SetResources(r)
	blocker, _ := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 4096)
	res := m.Inspect(st, failClosedSeg(100, 1, 2))
	if !stateLimit(res.Err) || len(m.bindings) != 0 || len(m.reassembler.streams) != 0 {
		t.Fatalf("refused admission retained state: %+v", res)
	}
	blocker.Release()
	m.FailStream(st, failClosedSeg(100), StreamDecoderPanic)
	if len(m.bindings) != 0 || len(m.reassembler.streams) != 0 || r.Budget.Status().InUse != 0 {
		t.Fatal("FailStream created a refused stream")
	}
}

func TestManagerHistoryRefusalPrecedesEvents(t *testing.T) {
	m, dec, st := framedFixture()
	r := limits.NewResources(limits.NewBudget(8192), nil)
	m.SetResources(r)
	m.Inspect(st, synSeg(100, true))
	// Allocate the new stream buffer, but leave no room to copy the parsed
	// bytes into strict history. No successful decoder event may escape.
	used := r.Budget.Status().InUse
	blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 8192-used-2)
	if !ok {
		t.Fatal("blocker")
	}
	res := m.Inspect(st, failClosedSeg(100, 1, 2))
	if !stateLimit(res.Err) || len(res.Events) != 0 || len(res.Frames) != 0 || dec.onPacketCalls != 0 {
		t.Fatalf("published an uncommitted inspection: %+v", res)
	}
	blocker.Release()
	res = m.Inspect(st, failClosedSeg(100, 1, 2))
	if !res.Failed || !stateLimit(res.Err) {
		t.Fatalf("refused stream resumed: %+v", res)
	}
	hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Mode != limits.ModeEnforce || hits[0].Total != 1 {
		t.Fatalf("refusal was not counted once: %+v", hits)
	}
	m.OnFlowEnd(st)
	m.OnFlowEnd(st)
	if r.Budget.Status().InUse != 0 || len(m.bindings) != 0 {
		t.Fatal("leaked owner credit")
	}
}

func TestManagerBindingsRefundSessionAndWireOwners(t *testing.T) {
	m, _, st := framedFixture()
	r := limits.NewResources(limits.NewBudget(16384), nil)
	m.SetResources(r)
	res := m.Inspect(st, sessionSeg("s", ClientToServer, 0, 1, 2))
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if len(m.bindings) != 2 || r.Budget.Status().InUse == 0 {
		t.Fatal("side maps were not charged")
	}
	m.EndStream("s")
	if len(m.bindings) != 1 {
		t.Fatal("wire timestamp lost its ownership")
	}
	m.OnFlowEnd(st)
	if len(m.bindings) != 0 || r.Budget.Status().InUse != 0 {
		t.Fatal("wire or session binding leaked")
	}
}

type budgetFramer struct{ mockStreamDecoder }

func (*budgetFramer) Protocol() string { return "modbus" }
func (*budgetFramer) ParseStream(_ *flow.State, _ StreamView) (StreamResult, error) {
	return StreamResult{}, &StreamError{Kind: StreamStateLimit}
}

func TestObservationManagerBudgetSharesHeadroom(t *testing.T) {
	m, err := NewObservationManager(&budgetFramer{})
	if err != nil {
		t.Fatal(err)
	}
	r := limits.NewResources(limits.NewBudget(4096), nil)
	m.SetResources(r)
	_, _, st := framedFixture()
	// Leave enough total capacity for one enforcing binding, but not for an
	// observation binding at the three-quarter ceiling.
	blocker, _ := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 3000)
	res := m.InspectProtocol("modbus", st, sessionSeg("s", ClientToServer, 0, 1, 2))
	var se *StreamError
	if !errors.As(res.Err, &se) || se.Kind != StreamStateLimit || len(m.bindings) != 0 {
		t.Fatalf("observation bypassed headroom: %+v", res)
	}
	blocker.Release()
	m.EndStream("s")
	if r.Budget.Status().InUse != 0 {
		t.Fatal("observation admission leaked")
	}
}
