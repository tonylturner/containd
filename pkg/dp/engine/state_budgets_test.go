// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestStateBudgets(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor", "mixed"} {
		t.Run("churn/"+mode, func(t *testing.T) { testStateBudgetChurn(t, mode) })
	}
	t.Run("headroom", testStateBudgetHeadroom)
	t.Run("flow_headroom", testStateBudgetFlowHeadroom)
	t.Run("refusal_sweeps", testStateBudgetRefusalSweeps)
	t.Run("inspection_refusal", testStateBudgetInspectionRefusal)
	t.Run("observation_refusal", testStateBudgetObservationRefusal)
	t.Run("stalled_completions", testStateBudgetCompletions)
	t.Run("reconfigure_under_load", testStateBudgetReconfigure)
	t.Run("capture_rebind", testStateBudgetRebind)
}

func testStateBudgetChurn(t *testing.T, mode string) {
	const offered = 88 // More than ten times the directional flow-slot limit.
	c := &stateBudgetClock{}
	c.nanos.Store(time.Now().UnixNano())
	e := stateBudgetEngine(t, limits.Limits{MaxFlows: 8, MaxTopTalkers: 2, MaxInspectionBytes: 65536}, limits.NewLedger(c.now), c)
	want := map[stateBudgetHit]uint64{}
	var legacy, observed bool
	for wave := range 3 {
		for i := range offered {
			enforce := mode == "enforce" || mode == "mixed" && i%2 == 1
			before := e.LimitOccupancy().Entries
			ceiling := int64(6)
			if enforce {
				ceiling = 8
			}
			admitted := before+2 <= ceiling
			for pi, p := range stateBudgetTrace(wave*offered+i, enforce, c.now()) {
				d := e.HandlePacket(p)
				expected := capture.Repeat
				if enforce && !admitted {
					expected = capture.Drop
				}
				if d.Action != expected || !admitted && enforce && d.Reason != "state_limit" {
					t.Fatalf("wave %d identity %d packet %d: %+v want %v", wave, i, pi, d, expected)
				}
				if !admitted {
					m := limits.ModeMonitor
					if enforce {
						m = limits.ModeEnforce
					}
					want[stateBudgetHit{limits.TableFlows, limits.ReasonRefused, m}]++
				}
				assertStateBudgetCaps(t, e)
			}
			// Retained directional host pairs evict both rows after the first
			// admitted identity; refused packets still count in protocol totals.
			if admitted && wave*offered+i > 0 {
				want[stateBudgetHit{limits.TableTopTalkers, limits.ReasonEvicted, limits.ModeObserve}] += 2
			}
		}
		for _, ev := range e.Events().List(0) {
			if ev.Proto == "modbus" && ev.Kind == "request" {
				if ev.Attributes["observation_only"] == true {
					observed = true
				} else {
					legacy = true
				}
			}
		}
		assertStateBudgetHits(t, e, want)
		var packets int64
		for _, row := range e.stats.Stats() {
			packets += row.PacketCount
		}
		if packets != int64((wave+1)*offered*4) {
			t.Fatalf("packet accounting under refusal: %d", packets)
		}
		c.advance(6 * time.Minute) // Both the 30 s opening TTL and 5 min established TTL.
		e.sweepFlows(c.now())
		e.sessions.expire()
		assertStateBudgetCaps(t, e)
		if e.LimitOccupancy().Entries != 0 {
			t.Fatal("expired flows retained")
		}
		assertStateBudgetEmpty(t, e.budget)
	}
	if mode != "monitor" && !legacy || mode != "enforce" && !observed {
		t.Fatalf("managers not exercised: legacy=%t observation=%t", legacy, observed)
	}
	e.Close()
	e.Close()
	assertStateBudgetEmpty(t, e.budget)
	assertStateBudgetCaps(t, e)
	assertStateBudgetHits(t, e, want)
}

func testStateBudgetHeadroom(t *testing.T) {
	c := &stateBudgetClock{}
	c.nanos.Store(time.Now().UnixNano())
	e := stateBudgetEngine(t, limits.Limits{MaxFlows: 8, MaxTopTalkers: 2, MaxInspectionBytes: 4096}, nil, c)
	// Stalled tokens are real IEC settlement-owner leases sharing the budget
	// used by both managers. Observe may retain only 3072 of the 4096 bytes.
	const charge = 1 + limits.HeldPacketHeaderAllowanceBytes + limits.HeldTokenMetadataBytes
	for i := range 88 {
		e.sessions.mu.Lock()
		ok := e.sessions.holdCreditLocked(capture.NewToken(1, uint32(i+1)), 1, false, "iec104")
		e.sessions.mu.Unlock()
		if ok != (i < 3) {
			t.Fatalf("monitor token %d admitted=%t", i, ok)
		}
		s := assertStateBudgetCaps(t, e)
		if s.Budget.InUse > 3*s.Budget.Limit/4 {
			t.Fatal("monitor consumed reserved headroom")
		}
	}
	e.sessions.mu.Lock()
	ok := e.sessions.holdCreditLocked(capture.NewToken(2, 1), 1, true, "iec104")
	e.sessions.mu.Unlock()
	if !ok || e.budget.Status().InUse != 4*charge {
		t.Fatal("monitor flood starved enforcement")
	}
	assertStateBudgetCaps(t, e)
	e.Close()
	assertStateBudgetEmpty(t, e.budget)
	assertStateBudgetHits(t, e, map[stateBudgetHit]uint64{})
}

func testStateBudgetFlowHeadroom(t *testing.T) {
	c := &stateBudgetClock{}
	c.nanos.Store(time.Now().UnixNano())
	e := stateBudgetEngine(t, limits.Limits{MaxFlows: 8, MaxTopTalkers: 2, MaxInspectionBytes: 65536}, nil, c)
	for id := range 88 {
		if d := e.HandlePacket(stateBudgetTrace(id, false, c.now())[0]); d.Action != capture.Repeat {
			t.Fatal(d)
		}
		assertStateBudgetCaps(t, e)
	}
	if e.LimitOccupancy().Entries != 6 {
		t.Fatal("monitor did not stop at three quarters")
	}
	if d := e.HandlePacket(stateBudgetTrace(100, true, c.now())[0]); d.Action != capture.Repeat {
		t.Fatal("monitor flood starved enforcement", d)
	}
	if e.LimitOccupancy().Entries != 8 {
		t.Fatal("enforce did not use reserved slots")
	}
	assertStateBudgetCaps(t, e)
	assertStateBudgetHits(t, e, map[stateBudgetHit]uint64{
		{limits.TableFlows, limits.ReasonRefused, limits.ModeMonitor}:      85,
		{limits.TableTopTalkers, limits.ReasonEvicted, limits.ModeObserve}: 2,
	})
	e.Close()
	assertStateBudgetEmpty(t, e.budget)
}

func testStateBudgetRefusalSweeps(t *testing.T) {
	c := &stateBudgetClock{}
	c.nanos.Store(time.Now().UnixNano())
	e := stateBudgetEngine(t, limits.Limits{MaxFlows: 8, MaxTopTalkers: 2, MaxInspectionBytes: 65536}, nil, c)
	for i := range 3 {
		e.HandlePacket(stateBudgetTrace(i, false, c.now())[0])
		assertStateBudgetCaps(t, e)
	}
	p := stateBudgetTrace(99, false, c.now())[0]
	if d := e.HandlePacket(p); d.Action != capture.Repeat || e.LimitOccupancy().Entries != 6 {
		t.Fatal("expected monitor capacity refusal", d)
	}
	assertStateBudgetCaps(t, e)
	// Not yet the scheduled 30 s sweep: the pressure path must do its
	// rate-limited pass and reclaim the now-expired opening reservations.
	c.advance(31 * time.Second)
	e.lastSweep = c.now()
	p.Timestamp = c.now()
	if d := e.HandlePacket(p); d.Action != capture.Repeat || e.LimitOccupancy().Entries != 2 {
		t.Fatal("refused before capacity sweep", d)
	}
	assertStateBudgetCaps(t, e)
	// Non-ICS, non-queued traffic retains ordinary firewall decisions even
	// while every slot is full. This is not a live management-path proof.
	for i := range 3 {
		q := stateBudgetTrace(110+i, false, c.now())[0]
		q.DstPort = 443
		q.Token = capture.Token{}
		q.HasMark, q.Mark, q.Queue = false, 0, nil
		e.HandlePacket(q)
		assertStateBudgetCaps(t, e)
	}
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		e.LoadRules(rules.Snapshot{Default: action})
		q := stateBudgetTrace(120, false, c.now())[0]
		q.DstPort = 443
		q.Token = capture.Token{}
		q.HasMark, q.Mark, q.Queue = false, 0, nil
		d := e.HandlePacket(q)
		// Ordinary firewall policy is kernel-owned: non-queued packets pass
		// through the engine before and during pressure, even for default deny.
		expected := capture.Accept
		if d.Action != expected {
			t.Errorf("ordinary %s policy under pressure: %+v", action, d)
		}
		assertStateBudgetCaps(t, e)
	}
	assertStateBudgetHits(t, e, map[stateBudgetHit]uint64{
		{limits.TableFlows, limits.ReasonRefused, limits.ModeMonitor}:      4,
		{limits.TableTopTalkers, limits.ReasonEvicted, limits.ModeObserve}: 4,
	})
	e.Close()
	assertStateBudgetEmpty(t, e.budget)
}

func testStateBudgetInspectionRefusal(t *testing.T) {
	for _, protocol := range firstCommandProtocols() {
		t.Run(protocol.name, func(t *testing.T) {
			for _, mode := range []string{"enforce", "monitor"} {
				t.Run(mode, func(t *testing.T) {
					f := newModeFlow(t, mode, protocol.port)
					t.Cleanup(f.e.Close)
					f.syn()
					b := f.e.budget
					s := b.Status()
					blocker, ok := b.Reserve(limits.ClassEnforce, limits.CategoryHeld, s.Limit-s.InUse)
					if !ok {
						t.Fatal("reserve pressure")
					}
					defer blocker.Release()
					for i := range 88 {
						d := f.decide(1, capture.TCPFlagACK|capture.TCPFlagPSH, protocol.read(1))
						want := capture.Drop
						if mode == "monitor" {
							want = capture.Repeat
						}
						if d.Action != want || i == 0 && mode == "enforce" && d.Reason != "state_limit" {
							t.Fatalf("refused inspection forwarded denied bytes: %+v", d)
						}
						assertStateBudgetCaps(t, f.e)
					}
					for _, ev := range f.e.Events().List(0) {
						if ev.Proto == protocol.name && ev.Kind == "request" {
							t.Fatal("refused inspection published a request")
						}
					}
					assertStateBudgetHits(t, f.e, map[stateBudgetHit]uint64{{limits.TableInspection, limits.ReasonRefused, limits.Mode(mode)}: 1})
					blocker.Release()
					f.e.Close()
					f.e.Close()
					assertStateBudgetEmpty(t, b)
				})
			}
		})
	}
}

func testStateBudgetObservationRefusal(t *testing.T) {
	c := &stateBudgetClock{}
	c.nanos.Store(time.Now().UnixNano())
	e := stateBudgetEngine(t, limits.Limits{MaxFlows: 8, MaxTopTalkers: 2, MaxInspectionBytes: 1}, nil, c)
	for id := range 88 {
		for _, p := range stateBudgetTrace(id, false, c.now()) {
			if d := e.HandlePacket(p); d.Action != capture.Repeat {
				t.Fatal("observation pressure changed ordinary verdict", d)
			}
			assertStateBudgetCaps(t, e)
		}
	}
	for _, ev := range e.Events().List(0) {
		if ev.Proto == "modbus" && ev.Kind == "request" {
			t.Fatal("refused observation published a request")
		}
	}
	assertStateBudgetHits(t, e, map[stateBudgetHit]uint64{
		// Each of three connections refuses one observer context and both
		// directional legacy-manager bindings, once per owner transition.
		{limits.TableInspection, limits.ReasonRefused, limits.ModeMonitor}: 3 * (1 + 2),
		{limits.TableFlows, limits.ReasonRefused, limits.ModeMonitor}:      340,
		{limits.TableTopTalkers, limits.ReasonEvicted, limits.ModeObserve}: 4,
	})
	e.Close()
	assertStateBudgetEmpty(t, e.budget)
}

func testStateBudgetCompletions(t *testing.T) {
	for _, end := range []string{"shutdown", "reconfigure", "source_down"} {
		t.Run(end, func(t *testing.T) {
			h := newIECHarness(t, "enforce")
			t.Cleanup(h.e.Close)
			h.handshake()
			p, d := h.send(true, iframe(46, 1)[:3])
			if d.Action != capture.Hold {
				t.Fatal(d)
			}
			assertStateBudgetCaps(t, h.e)
			_, d = h.send(true, iframe(46, 1)[3:])
			if d.Action != capture.Repeat || len(d.Resolved) != 1 {
				t.Fatal(d)
			}
			b, oldHooks := h.e.budget, h.e.hooks
			if b.Status().ByCategory["held"] != 3+limits.HeldPacketHeaderAllowanceBytes+limits.HeldTokenMetadataBytes {
				t.Fatal("premature settlement refund")
			}
			assertStateBudgetCaps(t, h.e)
			switch end {
			case "shutdown":
				h.e.Close()
			case "reconfigure":
				fresh, err := New(Config{Ledger: h.e.Ledger(), Limits: limits.Limits{MaxFlows: 8, MaxInspectionBytes: 8192}})
				if err != nil {
					t.Fatal(err)
				}
				if err = h.e.Reconfigure(fresh); err != nil {
					t.Fatal(err)
				}
			case "source_down":
				oldHooks.onSource(capture.SourceEvent{Generation: 1, Terminal: true, Err: capture.ErrTokenFlushed})
				h.e.Close()
			}
			assertStateBudgetEmpty(t, b)
			// Concurrent and duplicate late callbacks must not refund a new generation.
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() { oldHooks.onVerdict(p.Token, capture.VerdictRepeat, nil) })
			}
			wg.Wait()
			assertStateBudgetEmpty(t, b)
			assertStateBudgetCaps(t, h.e)
			assertStateBudgetHits(t, h.e, map[stateBudgetHit]uint64{})
		})
	}
}

// A decoder barrier makes the retirement/admission overlap reproducible, rather
// than relying on scheduler luck during a flood. It owns no retained buffers.
type stateBudgetRetirementBarrier struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*stateBudgetRetirementBarrier) Supports(*flow.State) bool { return true }
func (*stateBudgetRetirementBarrier) OnPacket(*flow.State, *dpi.ParsedPacket) ([]dpi.Event, error) {
	return nil, nil
}
func (d *stateBudgetRetirementBarrier) OnFlowEnd(*flow.State) ([]dpi.Event, error) {
	d.once.Do(func() { close(d.entered); <-d.release })
	return nil, nil
}

func testStateBudgetReconfigure(t *testing.T) {
	c := &stateBudgetClock{}
	c.nanos.Store(time.Now().UnixNano())
	ledger := limits.NewLedger(c.now)
	l := limits.Limits{MaxFlows: 8, MaxTopTalkers: 2, MaxInspectionBytes: 65536}
	e := stateBudgetEngine(t, l, ledger, c)
	gate := &stateBudgetRetirementBarrier{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	e.dpiMgr = dpi.NewManager(gate)
	e.dpiMgr.SetResources(e.inspectionResources())
	e.sessions.dpi = e.dpiMgr
	p := stateBudgetTrace(0, true, c.now())[0]
	if d := e.HandlePacket(p); d.Action != capture.Repeat {
		t.Fatal(d)
	}
	assertStateBudgetCaps(t, e)
	old := e.budget
	fresh := stateBudgetEngine(t, l, ledger, c)
	replaced := make(chan error, 1)
	go func() { replaced <- e.Reconfigure(fresh) }()
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("retirement did not reach decoder barrier")
	}
	// An already-dispatched packet attempts admission while retirement is
	// paused. If publication is already fenced it correctly waits for the new
	// generation; otherwise make its entry into the old owners deterministic.
	loaded := make(chan capture.Decision, 1)
	go func() { loaded <- e.HandlePacket(stateBudgetTrace(1, true, c.now())[0]) }()
	if e.policyMu.TryRLock() {
		e.policyMu.RUnlock()
		deadline := time.Now().Add(2 * time.Second)
		for e.LimitOccupancy().Entries == 0 && time.Now().Before(deadline) {
			runtime.Gosched()
		}
		if e.LimitOccupancy().Entries == 0 {
			t.Error("unfenced load did not reach admission")
		}
	}
	occupancy := e.LimitOccupancy()
	if occupancy.Entries > int64(l.MaxFlows) || old.Status().InUse > l.MaxInspectionBytes {
		t.Error("retiring generation exceeded caps", occupancy, old.Status())
	}

	release()
	select {
	case d := <-loaded:
		if d.Action != capture.Repeat {
			t.Error(d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("load did not finish")
	}
	select {
	case err := <-replaced:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reconfigure did not finish")
	}
	assertStateBudgetEmpty(t, old)
	assertStateBudgetCaps(t, e)
	if e.budget == old || e.Ledger() != ledger {
		t.Fatal("configuration lifetime mismatch")
	}
	assertStateBudgetHits(t, e, map[stateBudgetHit]uint64{})
	e.Close()
	assertStateBudgetEmpty(t, e.budget)
}

func testStateBudgetRebind(t *testing.T) {
	c := &stateBudgetClock{}
	c.nanos.Store(time.Now().UnixNano())
	e := stateBudgetEngine(t, limits.Limits{MaxFlows: 8, MaxTopTalkers: 2, MaxInspectionBytes: 65536}, nil, c)
	e.nfqueueGroup = 101
	e.captureFactory = func(capture.Config) (CaptureRunner, error) { return &bindCapture{}, nil }
	e.bindProtection(true)
	for id := range 2 {
		for _, p := range stateBudgetTrace(id, id == 0, c.now()) {
			e.HandlePacket(p)
			assertStateBudgetCaps(t, e)
		}
	}
	baseline := e.budget.Status().InUse
	if baseline == 0 {
		t.Fatal("missing retained manager state")
	}
	legacy, observer := e.dpiMgr, e.observation
	for i := range 3 {
		b, table, epoch := e.budget, e.sessions, e.epoch.Load()
		tok := capture.NewToken(uint64(i+1), 1)
		table.mu.Lock()
		ok := table.holdCreditLocked(tok, 1, true, "iec104")
		table.mu.Unlock()
		if !ok {
			t.Fatal("hold admission")
		}
		assertStateBudgetCaps(t, e)
		old := e.hooks
		old.onSource(capture.SourceEvent{Generation: uint64(i + 1), Terminal: true, Err: capture.ErrQueueClosed})
		if b.Status().InUse != baseline {
			t.Fatal("source flush changed non-held owner credit", b.Status())
		}
		if err := e.RetryProtection(context.Background()); err != nil {
			t.Fatal(err)
		}
		if e.epoch.Load() != epoch+1 || e.budget != b || e.sessions != table || old == e.hooks || e.dpiMgr != legacy || e.observation != observer {
			t.Fatal("capture retry rebuilt configuration owners or did not rebind")
		}
		// Reusing a kernel packet ID in a new capture generation must not allow
		// an old completion to refund its credit.
		next := capture.NewToken(uint64(i+2), 1)
		table.mu.Lock()
		ok = table.holdCreditLocked(next, 1, true, "iec104")
		table.mu.Unlock()
		if !ok {
			t.Fatal("new generation admission")
		}
		old.onVerdict(tok, capture.VerdictDrop, nil)
		if b.Status().ByCategory["held"] != 1+limits.HeldPacketHeaderAllowanceBytes+limits.HeldTokenMetadataBytes {
			t.Fatal("stale callback refunded new token")
		}
		e.hooks.onVerdict(next, capture.VerdictRepeat, nil)
		assertStateBudgetCaps(t, e)
		if b.Status().InUse != baseline {
			t.Fatal("rebind changed retained manager credit", b.Status())
		}
	}
	e.Close()
	assertStateBudgetEmpty(t, e.budget)
	assertStateBudgetHits(t, e, map[stateBudgetHit]uint64{{limits.TableTopTalkers, limits.ReasonEvicted, limits.ModeObserve}: 2})
	t.Log("capture-only retries retained configuration budget; live management not exercised")
}
