// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/session"
)

func sameProtectionSemantics(a, b ProtectionStatus) bool {
	a.ObservedAt, b.ObservedAt = time.Time{}, time.Time{}
	for i := range a.Components {
		a.Components[i].Since = time.Time{}
	}
	for i := range b.Components {
		b.Components[i].Since = time.Time{}
	}
	for i := range a.Subsystems {
		a.Subsystems[i].ObservedAt = time.Time{}
	}
	for i := range b.Subsystems {
		b.Subsystems[i].ObservedAt = time.Time{}
	}
	return reflect.DeepEqual(a, b)
}

func TestProtectionSemanticComparisonDetectsRetiredSourceChange(t *testing.T) {
	observed := time.Now()
	before := ProtectionStatus{
		State: "pending",
		Components: []ProtectionComponent{{
			Name: "nfqueue:101", State: "pending", Reason: "awaiting queue bind",
			Since: observed,
		}},
		Subsystems: []protection.OwnerOutcome{{
			Name: protection.SubsystemName("nfqueue:101"), State: protection.DeliveryPending,
			Reason: "awaiting queue bind", ObservedAt: observed,
		}},
		ObservedAt: observed,
	}
	after := before
	after.Components = append([]ProtectionComponent(nil), before.Components...)
	after.Subsystems = append([]protection.OwnerOutcome(nil), before.Subsystems...)
	after.ObservedAt = observed.Add(time.Second)
	after.Components[0].Since = observed.Add(time.Second)
	after.Subsystems[0].ObservedAt = observed.Add(time.Second)
	if !sameProtectionSemantics(before, after) {
		t.Fatal("timestamp-only recompute changed protection semantics")
	}

	after.State = "failed"
	after.Components[0].State = "failed"
	after.Components[0].Reason = "nfqueue:101: stale terminal event"
	after.Subsystems[0].State = protection.DeliveryFailed
	after.Subsystems[0].Reason = after.Components[0].Reason
	if sameProtectionSemantics(before, after) {
		t.Fatal("semantic comparison ignored injected retired-source state change")
	}
}

type joiningCapture struct {
	bindCapture
	entered, release, stopped chan struct{}
	once                      sync.Once
}

func (c *joiningCapture) Stop() {
	c.once.Do(func() { close(c.entered); <-c.release; close(c.stopped) })
}

func TestProtectionRetryJoinsDeadRunBeforeCreatingReplacement(t *testing.T) {
	old := &joiningCapture{entered: make(chan struct{}), release: make(chan struct{}), stopped: make(chan struct{})}
	nft := &nftModel{}
	e := gateEngine(t, nft, 101, old)
	t.Cleanup(e.Close)
	e.BeginProtection("boot", "retry")
	applyIEC(t, e)
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldHooks, oldDone, oldEpoch := e.hooks, e.runDone, e.epoch.Load()
	oldHooks.onSource(capture.SourceEvent{Ready: true})
	oldHooks.onSource(capture.SourceEvent{Terminal: true, Err: errBind})
	next := &bindCapture{}
	created := make(chan struct{})
	e.captureFactory = func(cfg capture.Config) (CaptureRunner, error) {
		select {
		case <-old.stopped:
		default:
			t.Error("replacement created before old consumer joined")
		}
		select {
		case <-oldDone:
		default:
			t.Error("replacement created before run workers joined")
		}
		if cfg.PublicationFence != &e.policyMu {
			t.Error("replacement lost publication fence")
		}
		next.onReady = func() { cfg.OnSource(capture.SourceEvent{Ready: true}) }
		close(created)
		return next, nil
	}
	done := make(chan error, 1)
	go func() { done <- e.RetryProtection(context.Background()) }()
	select {
	case <-old.entered:
	case <-time.After(time.Second):
		t.Fatal("retry did not stop old consumer")
	}
	select {
	case <-created:
		t.Error("replacement overlapped consumer retirement")
	default:
	}
	close(old.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if e.capture != next || e.epoch.Load() != oldEpoch+1 {
		t.Fatal("retry bypassed the configured capture factory")
	}
	before := e.Protection()
	oldHooks.onSource(capture.SourceEvent{Ready: true})
	assertUnchanged := func() {
		t.Helper()
		after := e.Protection()
		if !sameProtectionSemantics(before, after) {
			t.Fatalf("retired source changed protection semantics: before=%+v after=%+v", before, after)
		}
	}
	assertUnchanged()
	wantEnvelope(t, nft, "drop", "stale Ready before replacement bind")
	if err := e.StartProtection(context.Background(), context.Background()); err != nil {
		t.Fatal(err)
	}
	before = e.Protection()
	oldHooks.onSource(capture.SourceEvent{Terminal: true, Err: errBind})
	assertUnchanged()
	wantEnvelope(t, nft, "queue 101", "stale loss after replacement bind")
	if before.State != "protecting" || next.starts.Load() != 1 {
		t.Fatalf("replacement: %+v starts=%d", before, next.starts.Load())
	}
}

func TestProtectionNewRunUsesConfiguredCaptureFactory(t *testing.T) {
	var source func(capture.SourceEvent)
	runner := &bindCapture{}
	e, err := New(Config{
		NFQueueGroup: 101, ResetInjector: &session.Fake{},
		NewCapture: func(cfg capture.Config) (CaptureRunner, error) {
			source = cfg.OnSource
			if cfg.PublicationFence == nil || cfg.OnVerdict == nil {
				t.Error("initial run lost capture callbacks or publication fence")
			}
			return runner, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	if e.capture != runner || source == nil || e.iec.jobs != e.hooks.blocks {
		t.Fatal("New bypassed shared run wiring")
	}
	source(capture.SourceEvent{Ready: true})
	if protectionComponent(t, e.Protection(), "nfqueue:101").State != "ready" {
		t.Fatal("factory did not receive current source hooks")
	}
}

func TestProtectionFailedReplacementStillFencesRetiredCallbacks(t *testing.T) {
	e := protectionFixture(t, false)
	t.Cleanup(e.Close)
	old := e.hooks
	old.onSource(capture.SourceEvent{Terminal: true, Err: errBind})
	e.captureFactory = func(capture.Config) (CaptureRunner, error) { return nil, errBind }
	if err := e.RetryProtection(context.Background()); !errors.Is(err, errBind) {
		t.Fatalf("replacement construction: %v", err)
	}
	before := e.Protection()
	old.onSource(capture.SourceEvent{Ready: true})
	after := e.Protection()
	if !sameProtectionSemantics(before, after) {
		t.Fatalf("failed replacement allowed retired callbacks to change protection semantics: before=%+v after=%+v", before, after)
	}
	e.gate.mu.Lock()
	owned := e.gate.owned
	e.gate.mu.Unlock()
	if owned != 0 {
		t.Fatal("failed replacement allowed retired callbacks to reopen envelope")
	}
}
