// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func protectionComponent(t *testing.T, st ProtectionStatus, name string) ProtectionComponent {
	t.Helper()
	for _, c := range st.Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("component %s absent: %+v", name, st)
	return ProtectionComponent{}
}

func protectionFixture(t *testing.T, monitor bool) *Engine {
	t.Helper()
	e := inlineEngine(t, &bindCapture{})
	// No nft subprocess: observe the same installed queue policy as the kernel.
	e.compiler = enforce.NewCompilerWithSettings(enforce.CompilerSettings{NFQueueGroup: 101}, nil)
	e.clearMarks = func(context.Context, uint32, uint32, uint32) (int, error) { return 0, nil }
	e.bindGate()
	e.bindProtection(true)
	e.BeginProtection("boot", "A")
	e.LoadRules(iecSnapshot(map[bool]string{true: "monitor", false: "enforce"}[monitor]))
	e.protectionInstalled(nil, true)
	return e
}

func TestProtectionRunAdoptionAndStaleCallbacks(t *testing.T) {
	e := protectionFixture(t, false)
	if st := e.Protection(); st.State != "pending" {
		t.Fatalf("before bind: %+v", st)
	}
	e.hooks.onSource(capture.SourceEvent{Ready: true, Generation: 1})
	if st := e.Protection(); st.State != "protecting" {
		t.Fatalf("ready: %+v", st)
	}
	e.BeginProtection("boot", "B")
	if st := e.Protection(); st.State != "pending" || st.InstalledApplyID != "A" {
		t.Fatalf("begin: %+v", st)
	}
	e.protectionInstalled(nil, true)
	if st := e.Protection(); st.State != "protecting" || st.InstalledApplyID != "B" {
		t.Fatalf("adopted: %+v", st)
	}
	old := e.hooks
	fresh, _ := New(Config{Events: e.Events(), NFQueueGroup: 101})
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	before := e.Protection()
	old.onSource(capture.SourceEvent{Ready: true, Generation: 2})
	after := e.Protection()
	before.ObservedAt = after.ObservedAt
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("retired callback changed observation: before=%+v after=%+v", before, after)
	}
	if c := protectionComponent(t, after, "nfqueue:101"); c.State != "pending" {
		t.Fatal("retired callback advanced replacement")
	}
	e.gate.mu.Lock()
	owned := e.gate.owned
	e.gate.mu.Unlock()
	if owned != 0 {
		t.Fatalf("retired callback reopened envelope ownership: %d", owned)
	}
}

func TestProtectionFailedEventPrefersFailedComponentReason(t *testing.T) {
	e := protectionFixture(t, false)
	e.protection.update(func() { e.protection.setLocked("iec-envelope", "pending", "", 0, 0) })
	e.hooks.onSource(capture.SourceEvent{Terminal: true, Err: errBind})
	for _, ev := range e.Events().List(0) {
		if ev.Kind == "protection.state" && ev.Attributes["state"] == "failed" {
			reason, _ := ev.Attributes["reason"].(string)
			if !strings.HasPrefix(reason, "nfqueue:101: ") {
				t.Fatalf("failed transition lost its cause: %+v", ev)
			}
			return
		}
	}
	t.Fatal("missing failed transition event")
}

func TestProtectionRebindDropsRetiredQueueImmediately(t *testing.T) {
	e := protectionFixture(t, false)
	e.hooks.onSource(capture.SourceEvent{Ready: true})
	fresh, err := New(Config{NFQueueGroup: 102, Enforce: EnforceConfig{Enabled: true}, ResetInjector: e.iec.injector})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	for _, c := range e.Protection().Components {
		if c.Name == "nfqueue:101" {
			t.Fatalf("retired queue still published before ApplyRules: %+v", c)
		}
	}
}

func TestProtectionEffectsAndDisabled(t *testing.T) {
	for _, monitor := range []bool{false, true} {
		t.Run(map[bool]string{true: "monitor", false: "enforce"}[monitor], func(t *testing.T) {
			e := protectionFixture(t, monitor)
			e.hooks.onSource(capture.SourceEvent{Terminal: true, Err: errors.New("operation not permitted")})
			st := e.Protection()
			if st.State != "failed" || !st.Retryable {
				t.Fatalf("terminal: %+v", st)
			}
			c := protectionComponent(t, st, "nfqueue:101")
			if !strings.HasPrefix(c.Reason, "nfqueue:101: ") || strings.Contains(c.Reason, "another consumer") {
				t.Fatalf("reason: %s", c.Reason)
			}
			want := "fail_closed_drop"
			if monitor {
				want = "not_inspected"
			}
			if len(st.Effects) != 1 || st.Effects[0].Effect != want {
				t.Fatalf("effects: %+v", st.Effects)
			}
			st.Components[0].State = "corrupted"
			st.Effects[0].Effect = "corrupted"
			if e.Protection().Effects[0].Effect != want {
				t.Fatal("mutable snapshot")
			}
			e.protection.update(func() { e.protection.enabled = false })
			if e.Protection().State != "disabled" {
				t.Fatalf("disabled failed: %+v", e.Protection())
			}
		})
	}
}

func TestProtectionBoundedRetryAndFaults(t *testing.T) {
	fastRetry(t, 3)
	e := protectionFixture(t, false)
	e.capture = &bindCapture{fails: 100}
	if err := e.StartWithRetry(context.Background()); err == nil {
		t.Fatal("bind succeeded")
	}
	st := e.Protection()
	c := protectionComponent(t, st, "nfqueue:101")
	if st.State != "failed" || c.Attempt != 3 || c.MaxAttempts != 3 {
		t.Fatalf("exhausted: %+v", st)
	}
	e.hooks.onSource(capture.SourceEvent{Ready: true})
	e.iec.health.fault(faultWorker, "worker failed")
	if e.Protection().State != "failed" {
		t.Fatalf("worker loss: %+v", e.Protection())
	}
	e.iec.health.clear(faultWorker)
	if e.Protection().State != "protecting" {
		t.Fatalf("worker recovery: %+v", e.Protection())
	}
}

func TestProtectionGateAndNFLog(t *testing.T) {
	e := protectionFixture(t, false)
	snap := iecSnapshot("enforce")
	snap.Gate.Enabled = true
	e.LoadRules(snap)
	e.protectionInstalled(nil, true)
	e.hooks.onSource(capture.SourceEvent{Ready: true})
	e.SetScanProtection("ready", "", false, "starting", false)
	if e.Protection().State != "pending" {
		t.Fatalf("scanner unready: %+v", e.Protection())
	}
	e.SetScanProtection("failed", "admission failed", true, "", true)
	st := e.Protection()
	if st.State != "failed" || st.Effects[len(st.Effects)-1].Effect != "unknown" {
		t.Fatalf("admission failure: %+v", st)
	}
	e.SetScanProtection("ready", "", true, "", false)
	e.protection.update(func() { e.protection.setLocked("nflog", "failed", "lost", 3, 3) })
	if st = e.Protection(); st.State != "degraded" || !st.Retryable {
		t.Fatalf("NFLOG loss: %+v", st)
	}
	e.protection.update(func() { e.protection.setLocked("nflog", "ready", "", 0, 0) })
	if e.Protection().State != "protecting" {
		t.Fatalf("NFLOG recovered: %+v", e.Protection())
	}
	// Generic inspection uses the direct queue, never the enforcing envelope.
	e.LoadRules(rules.Snapshot{Firewall: []rules.Entry{{Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "modbus"}}}})
	e.protectionInstalled(nil, true)
	e.hooks.onSource(capture.SourceEvent{Terminal: true, Err: errBind})
	st = e.Protection()
	if len(st.Effects) != 1 || st.Effects[0].Effect != "not_inspected" {
		t.Fatalf("generic: %+v", st)
	}
}

func TestProtectionSteeringRetryKeepsHealthyConsumer(t *testing.T) {
	nft := &nftModel{}
	e := gateEngine(t, nft, 101, &bindCapture{})
	e.BeginProtection("boot", "steering")
	applyIEC(t, e)
	nft.mu.Lock()
	nft.failNext = true
	nft.mu.Unlock()
	e.hooks.onSource(capture.SourceEvent{Ready: true, Generation: 1})
	st := e.Protection()
	if st.State != "failed" || !st.Retryable || st.Effects[0].Effect != "unknown" {
		t.Fatalf("failed steering: %+v", st)
	}
	consumer := e.capture
	if err := e.RetryProtection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.capture != consumer {
		t.Fatal("steering retry retired healthy capture")
	}
	if st = e.Protection(); st.State != "protecting" {
		t.Fatalf("reconciled: %+v", st)
	}
	wantEnvelope(t, nft, "queue 101", "after explicit reconciliation")
}

func TestProtectionInstalledIdentityOnPostInstallFailure(t *testing.T) {
	e := protectionFixture(t, false)
	e.BeginProtection("boot", "B")
	e.protectionInstalled(errors.New("post-install sweep failed"), true)
	st := e.Protection()
	if st.State != "failed" || st.Retryable || st.InstalledApplyID != "B" || protectionComponent(t, st, "nft").State != "ready" {
		t.Fatalf("post-install failure: %+v", st)
	}
	e.BeginProtection("boot", "C")
	e.protectionInstalled(errors.New("nft transaction rejected"), false)
	st = e.Protection()
	if st.InstalledApplyID != "B" || st.State != "failed" || st.Retryable {
		t.Fatalf("failed install lost previous identity: %+v", st)
	}
}

func TestProtectionWaitsForServiceReconciliation(t *testing.T) {
	e := gateEngine(t, &nftModel{}, 101, &bindCapture{})
	e.BeginProtection("boot", "reconcile")
	e.hooks.onSource(capture.SourceEvent{Ready: true})
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- e.ApplyRulesAndReconcile(context.Background(), iecSnapshot("enforce"), func() { close(entered); <-release })
	}()
	<-entered
	if st := e.Protection(); st.State != "pending" || st.InstalledApplyID != "reconcile" {
		t.Errorf("reconciliation in flight: %+v", st)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if e.Protection().State != "protecting" {
		t.Fatalf("reconciled: %+v", e.Protection())
	}
}

type lostBeforeStartReturns struct {
	bindCapture
	source func(capture.SourceEvent)
}

func (c *lostBeforeStartReturns) Start(context.Context, capture.Handler) error {
	c.source(capture.SourceEvent{Ready: true, Generation: 1})
	c.source(capture.SourceEvent{Terminal: true, Err: errors.New("consumer lost before Start returned"), Generation: 1})
	return nil
}

func TestProtectionSourceLossBeforeStartReturns(t *testing.T) {
	nft := &nftModel{}
	c := &lostBeforeStartReturns{}
	e := gateEngine(t, nft, 101, c)
	t.Cleanup(e.Close)
	c.source = e.hooks.onSource
	e.BeginProtection("boot", "fast-loss")
	applyIEC(t, e)
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantEnvelope(t, nft, "drop", "source died after registration but before Start returned")
	if st := e.Protection(); st.State != "failed" || !st.Retryable {
		t.Fatalf("lost source: %+v", st)
	}
}

func TestProtectionReleaseClearsInstalledIdentity(t *testing.T) {
	e := gateEngine(t, &nftModel{}, 101, &bindCapture{})
	e.BeginProtection("boot", "enabled")
	applyIEC(t, e)
	fresh, err := New(Config{Events: e.Events(), NFQueueGroup: 101, ResetInjector: e.iec.injector})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	st := e.Protection()
	if st.State != "disabled" || st.InstalledApplyID != "" || protectionComponent(t, st, "nft").State != "off" {
		t.Fatalf("released policy: %+v", st)
	}
	e.hooks.onSource(capture.SourceEvent{Terminal: true, Err: errBind})
	if e.Protection().State != "disabled" || protectionComponent(t, e.Protection(), "nfqueue:101").State != "failed" {
		t.Fatalf("terminal loss made disabled enforcement fail: %+v", e.Protection())
	}
}

func TestProtectionOldQueueFaultDoesNotRetireAdoptedRun(t *testing.T) {
	e := protectionFixture(t, false)
	e.hooks.onSource(capture.SourceEvent{Ready: true})
	e.protection.update(func() { e.protection.setLocked("nfqueue:99", "failed", "retired queue", 3, 3) })
	e.BeginProtection("boot", "adopt")
	consumer, epoch := e.capture, e.epoch.Load()
	if err := e.RetryProtection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.capture != consumer || e.epoch.Load() != epoch {
		t.Fatal("retired queue failure restarted the healthy adopted consumer")
	}
	e.protectionInstalled(nil, true)
	if e.Protection().State != "protecting" {
		t.Fatalf("adoption: %+v", e.Protection())
	}
	for _, c := range e.Protection().Components {
		if c.Name == "nfqueue:99" {
			t.Fatal("retired queue remained in current observation")
		}
	}
}

func TestProtectionLoggingRetryDoesNotRewriteHealthySteering(t *testing.T) {
	nft := &nftModel{}
	e := gateEngine(t, nft, 101, &bindCapture{})
	e.BeginProtection("boot", "logging")
	applyIEC(t, e)
	e.hooks.onSource(capture.SourceEvent{Ready: true})
	e.protection.update(func() { e.protection.setLocked("nflog", "failed", "logging unavailable", 3, 3) })
	if e.Protection().State != "degraded" {
		t.Fatalf("logging failure: %+v", e.Protection())
	}
	_, before := nft.state()
	if err := e.RetryProtection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, after := nft.state(); after != before {
		t.Fatal("logging retry rewrote healthy envelope steering")
	}
}

func TestProtectionAdoptionPreservesNFLogRetryBudget(t *testing.T) {
	e := protectionFixture(t, false)
	stops := 0
	e.nflogStop = func() { stops++ }
	e.protection.update(func() { e.protection.setLocked("nflog", "pending", "retrying", 2, 8) })
	e.BeginProtection("boot", "next-apply")
	if err := e.RetryProtection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stops != 0 || protectionComponent(t, e.Protection(), "nflog").Attempt != 2 {
		t.Fatal("adoption restarted the independent NFLOG retry domain")
	}
}
