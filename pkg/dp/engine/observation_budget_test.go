// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/identify"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
)

func TestObservationContextsFollowFlowSlots(t *testing.T) {
	r := limits.NewResources(nil, nil)
	live, err := newLiveObserver(Config{Limits: limits.Limits{MaxFlows: 10000}}, r)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5000 {
		if !live.observer.Open(identify.Key(strconv.Itoa(i)), identify.Meta{Transport: 6}) {
			t.Fatalf("observer imposed a separate admission cap at %d", i)
		}
	}
	live.observer.Drain()
	if r.Budget.Status().InUse != 0 {
		t.Fatal("drain retained metadata")
	}
}

func TestObservationAdmissionBudgetLossIsReportedOnce(t *testing.T) {
	e, err := New(Config{Capture: capture.Config{Interfaces: []string{"eth0"}},
		DPIEnabled: true, Limits: limits.Limits{MaxInspectionBytes: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow})
	var losses atomic.Int32
	e.SetLearnLossHook(func(evidence.CollectionLoss) { losses.Add(1) })
	for _, pkt := range observationTrace(1502, false) {
		if d := e.HandlePacket(pkt); d.Action != capture.Accept {
			t.Fatalf("inspection refusal changed ordinary policy: %+v", d)
		}
	}
	if losses.Load() != 1 {
		t.Fatalf("admission loss reports = %d", losses.Load())
	}
	hits := e.ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Mode != limits.ModeMonitor || hits[0].Total != 1 {
		t.Fatal(hits)
	}
	if e.budget.Status().InUse != 0 {
		t.Fatal("refused admission retained credit")
	}
}
