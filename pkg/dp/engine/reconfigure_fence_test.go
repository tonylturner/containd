// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

type reconfigureFenceDecoder struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*reconfigureFenceDecoder) Supports(*flow.State) bool { return true }
func (*reconfigureFenceDecoder) OnPacket(*flow.State, *dpi.ParsedPacket) ([]dpi.Event, error) {
	return nil, nil
}
func (d *reconfigureFenceDecoder) OnFlowEnd(*flow.State) ([]dpi.Event, error) {
	d.once.Do(func() {
		close(d.entered)
		<-d.release
	})
	return nil, nil
}

func TestReconfigureFencesOwnerRetirement(t *testing.T) {
	e, err := New(Config{DPIEnabled: true, InspectAll: true, Limits: limits.Limits{MaxFlows: 8}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	gate := &reconfigureFenceDecoder{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	e.dpiMgr = dpi.NewManager(gate)
	e.dpiMgr.SetResources(e.inspectionResources())
	e.sessions.dpi = e.dpiMgr
	if d := e.HandlePacket(segment(false, 100, capture.TCPFlagSYN, nil)); d.Action != capture.Accept {
		t.Fatal(d)
	}
	old := e.budget
	if old.Status().InUse == 0 {
		t.Fatal("initial flow retained no inspection credit")
	}
	fresh, err := New(Config{DPIEnabled: true, InspectAll: true, Events: e.Events(), Ledger: e.Ledger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fresh.Close)
	replaced := make(chan error, 1)
	go func() { replaced <- e.Reconfigure(fresh) }()
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("retirement did not reach the decoder")
	}
	// Flow indexes are already cleared, but their decoder teardown is paused.
	// Publication must exclude admission throughout both stages.
	if e.policyMu.TryRLock() {
		e.policyMu.RUnlock()
		t.Error("owner retirement did not exclude packet admission")
	}
	if e.LimitOccupancy().Entries != 0 {
		t.Error("old flow slots were not cleared before decoder teardown")
	}
	loaded := make(chan capture.Decision, 1)
	go func() {
		loaded <- e.HandlePacket(connSegment(false, 41001, 502, 100, capture.TCPFlagSYN, nil))
	}()
	release()
	select {
	case err := <-replaced:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reconfigure did not finish")
	}
	select {
	case d := <-loaded:
		if d.Action != capture.Accept {
			t.Fatal(d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("direct packet did not finish")
	}
	if status := old.Status(); status.InUse != 0 {
		t.Fatalf("retired generation leaked credit: %+v", status)
	}
	if e.budget == old || e.budget.Status().InUse == 0 || e.LimitOccupancy().Entries != 2 {
		t.Fatal("direct packet did not enter the replacement generation")
	}
	e.Close()
	if status := e.budget.Status(); status.InUse != 0 {
		t.Fatalf("replacement generation leaked credit: %+v", status)
	}
}
