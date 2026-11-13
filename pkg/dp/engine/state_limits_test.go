// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

func TestStateLimitsInitialization(t *testing.T) {
	shared := limits.NewLedger(nil)
	for _, in := range []limits.Limits{{}, {MaxFlows: 2}, {MaxTopTalkers: 1, MaxInspectionBytes: 7}} {
		e, err := New(Config{Limits: in, Ledger: shared})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.Close)
		cfg := detachedTestConfig(events.NewStore(4))
		cfg.Limits = in
		d, err := NewDetached(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(d.Close)
		if e.stateLimits != d.engine.stateLimits || e.budget == d.engine.budget || e.Ledger() != shared || d.engine.Ledger() == shared {
			t.Fatal("constructor lifetime mismatch")
		}
		want := limits.Default()
		if in.MaxFlows != 0 {
			want.MaxFlows = in.MaxFlows
		}
		if in.MaxTopTalkers != 0 {
			want.MaxTopTalkers = in.MaxTopTalkers
		}
		if in.MaxInspectionBytes != 0 {
			want.MaxInspectionBytes = in.MaxInspectionBytes
		}
		if e.verdictCache.ledger != shared || e.conformance.ledger != shared || e.iec.pickups.ledger != shared {
			t.Fatal("observational engine owners lost process ledger")
		}
		if e.stateLimits != want || e.StateLimits().Budget.Limit != want.MaxInspectionBytes {
			t.Fatal("per-field defaults")
		}
	}
	for _, bad := range []limits.Limits{{MaxFlows: -1}, {MaxTopTalkers: -1}, {MaxInspectionBytes: -1}} {
		if e, err := New(Config{Limits: bad}); err == nil || e != nil {
			t.Fatal("negative live limits")
		}
		cfg := detachedTestConfig(events.NewStore(4))
		cfg.Limits = bad
		if d, err := NewDetached(cfg); err == nil || d != nil {
			t.Fatal("negative detached limits")
		}
	}
}
func TestStateLimitsCurrentOwnersAndReconfigure(t *testing.T) {
	ledger := limits.NewLedger(nil)
	e, err := New(Config{Ledger: ledger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	e.trackFlow(segment(false, 100, 0, nil), time.Now())
	e.verdictCache.Put("one", verdict.Verdict{})
	e.iec.mu.Lock()
	e.iec.reconnect["one"] = time.Now()
	e.iec.mu.Unlock()
	ledger.Record(limits.TableFlows, limits.ReasonRefused, limits.ModeEnforce)
	s := e.StateLimits()
	got := make(map[limits.Table]limits.TableStatus)
	for _, st := range s.Tables {
		got[st.Table] = st
	}
	if len(got) != 12 || got[limits.TableFlows].Entries != 2 || got[limits.TableFlows].Limit != limits.DefaultMaxFlows || got[limits.TableIECReconnect].Entries != 1 || got[limits.TableVerdictCache].Entries != 1 || got[limits.TableIECSessions].Limit != 4096 || got[limits.TableConformance].Limit != 65536 || got[limits.TablePickupReset].Limit != 4096 || got[limits.TableSignatureWindows].Limit != 4096 || got[limits.TableInventoryPoints].Limit != limits.MaxInventoryPoints {
		t.Fatalf("owners %+v", s)
	}
	oldBudget := e.budget
	l, _ := oldBudget.Reserve(limits.ClassEnforce, limits.CategoryStream, 1)
	defer l.Release()
	fresh, err := New(Config{Events: e.Events(), Ledger: ledger, Limits: limits.Limits{MaxInspectionBytes: 8}})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	after := e.StateLimits()
	if e.budget == oldBudget || after.Budget.Limit != 8 || after.Budget.InUse != 0 || after.Tables[0].Entries != 0 || len(after.Tables[0].Hits) != 1 || testutil.ToFloat64(metrics.FlowsActive) != 0 {
		t.Fatalf("adoption %+v", after)
	}
}
func TestStateLimitsConcurrentReconfigure(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 50 {
			s := e.StateLimits()
			if len(s.Tables) != 12 {
				t.Error("torn snapshot")
			}
			e.TopTalkers(1)
		}
	})
	for range 10 {
		fresh, err := New(Config{Ledger: e.Ledger(), Events: e.Events()})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Reconfigure(fresh); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
func TestStateLimitTransitionEvents(t *testing.T) {
	now := time.Unix(0, 0)
	ledger := limits.NewLedger(func() time.Time { return now })
	e, err := New(Config{Ledger: ledger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	ledger.Record(limits.TableVerdictCache, limits.ReasonEvicted, limits.ModeObserve)
	ledger.Record(limits.TableVerdictCache, limits.ReasonEvicted, limits.ModeObserve)
	e.publishStateLimitTransitions()
	e.publishStateLimitTransitions()
	var found []events.Event
	for _, ev := range e.Events().List(100) {
		if ev.Kind == "dataplane.state_limit" {
			found = append(found, ev)
		}
	}
	if len(found) != 1 || !reflect.DeepEqual(found[0].Attributes, map[string]any{"table": "verdict_cache", "reason": "evicted", "mode": "observe", "limit": int64(65536)}) {
		t.Fatalf("events %+v", found)
	}
}
