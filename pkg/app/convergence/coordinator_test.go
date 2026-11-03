// SPDX-License-Identifier: Apache-2.0

package convergence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestSameBootOutstandingOnly(t *testing.T) {
	c, _, engine, _, env, demo := fixture(t)
	engine.fail["interfaces"] = 1
	tick(t, c)
	ready(t, c, false)
	first := c.work.admission
	if engine.count("nft") != 1 || engine.count("routing") != 0 {
		t.Fatal("critical baseline or dependency order")
	}
	tick(t, c)
	ready(t, c, true)
	if c.work.admission != first {
		t.Fatal("same-input retry minted new attempt")
	}
	if engine.count("interfaces") != 2 || engine.count("nft") != 1 || engine.count("config") != 1 ||
		engine.count("trust") != 1 || engine.count("routing") != 1 {
		t.Fatalf("unrelated owner replay: %+v", engine.calls)
	}
	tick(t, c)
	if env.pcaps != 1 {
		t.Fatal("saved PCAP retried")
	}
	synced, reconciles, _ := demo.counts()
	if synced != 1 || reconciles != 3 {
		t.Fatalf("demo hooks: %d %d", synced, reconciles)
	}
}

func TestNonGatingFaultAndRequiredTeardown(t *testing.T) {
	for _, name := range []protection.SubsystemName{protection.SubsystemDNS, protection.SubsystemOpenVPN,
		protection.SubsystemForwardProxy, protection.SubsystemReverseProxy} {
		t.Run(string(name), func(t *testing.T) {
			c, _, engine, local, _, _ := fixture(t)
			local.failed = name
			tick(t, c)
			got := ready(t, c, name == protection.SubsystemDNS)
			if got.AppliedRevision == nil {
				t.Fatal("service fault erased installed identity")
			}
			// Desired is disabled throughout: only verified teardown discharges it.
			local.mu.Lock()
			local.failed = ""
			local.mu.Unlock()
			tick(t, c)
			ready(t, c, true)
			if engine.count("nft") != 1 {
				t.Fatal("teardown retry replayed healthy policy")
			}
		})
	}
}

func TestAuthorityAndObservationFences(t *testing.T) {
	c, store, engine, _, _, _ := fixture(t)
	tick(t, c)
	ready(t, c, true)
	store.mu.Lock()
	store.state.Revision = "candidate-only-CAS"
	store.mu.Unlock()
	tick(t, c)
	ready(t, c, true)
	if engine.count("nft") != 1 {
		t.Fatal("candidate CAS replay")
	}
	old := c.work.admission.Metadata
	store.mu.Lock()
	store.state.Running = detached(store.state.Running)
	store.state.Running.RunningRevision += "_new"
	store.mu.Unlock()
	ready(t, c, false)
	tick(t, c)
	got := ready(t, c, true)
	if *got.DesiredRevision == old.RunningRevision {
		t.Fatal("old revision remained desired")
	}
	if !errors.Is(c.Retry(old), ErrSuperseded) {
		t.Fatal("stale manual retry accepted")
	}
	engine.mu.Lock()
	engine.observation.BootID = "new_boot"
	engine.mu.Unlock()
	ready(t, c, false)
	tick(t, c)
	ready(t, c, true)
	engine.mu.Lock()
	engine.observation.Degraded = true
	engine.mu.Unlock()
	if ready(t, c, false).State != protection.StateDegraded {
		t.Fatal("schedule/logging override ignored")
	}
}

func TestRecoveryOrderAndDemoEligibility(t *testing.T) {
	c, store, engine, _, _, demo := fixture(t)
	tick(t, c)
	completes := store.completes
	store.state.Transition = &config.TransitionGuard{ID: "blocked", State: config.TransitionBlocked,
		RunningRevision: store.state.Running.RunningRevision}
	var order []string
	engine.hook = func(_ context.Context, phase string) error {
		order = append(order, phase)
		return nil
	}
	tick(t, c)
	if len(order) != 3 || order[0] != "config" || order[1] != "nft" || order[2] != "interfaces" {
		t.Fatalf("recovery order %v", order)
	}
	ready(t, c, false)
	if store.completes != completes {
		t.Fatal("blocked restoration was resolved by replay")
	}
	synced, _, _ := demo.counts()
	tick(t, c)
	syncedAfter, _, _ := demo.counts()
	if syncedAfter != synced {
		t.Fatal("demo restarted in recovery")
	}
}

func TestRestoredReplayAndCompensation(t *testing.T) {
	t.Run("restored-pending", func(t *testing.T) {
		c, store, _, _, _, _ := fixture(t)
		store.state.Transition = &config.TransitionGuard{ID: "restore", State: config.TransitionReapplyPending,
			RunningRevision: store.state.Running.RunningRevision}
		tick(t, c)
		ready(t, c, true)
		if store.completes != 1 {
			t.Fatal("restored guard not completed")
		}
	})
	t.Run("synchronous-compensation", func(t *testing.T) {
		c, store, engine, _, _, _ := fixture(t)
		previous := detached(store.state.Running)
		next := detached(previous)
		next.RunningRevision += "_rejected"
		restored := detached(previous)
		restored.RunningRevision += "_restored"
		engine.fail["nft"] = 1
		store.apply = func(ctx context.Context, apply func(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) error) error {
			firstErr := apply(ctx, previous, next)
			if firstErr == nil {
				t.Fatal("critical failure accepted")
			}
			// This read acquires the store lock and succeeds: callbacks do not
			// hold or recursively acquire it.
			if _, err := store.ReadRunning(ctx); err != nil {
				t.Fatal(err)
			}
			reapplyErr := apply(context.WithoutCancel(ctx), next, restored)
			store.state.Running = restored
			return &config.ApplyError{Err: firstErr, ReapplyError: reapplyErr}
		}
		result, err := c.Change(context.Background(), "cas", config.ChangeCommit, 0)
		var failure *config.ApplyError
		if !errors.As(err, &failure) || failure.ReapplyError != nil {
			t.Fatalf("compensation: %v", err)
		}
		if result.RunningRevision != restored.RunningRevision {
			t.Fatal("rejected target returned")
		}
		tick(t, c)
		ready(t, c, true)
		if c.work.snapshot.RunningRevision != restored.RunningRevision {
			t.Fatal("retry selected rejected generation")
		}
	})
	t.Run("newer-authority", func(t *testing.T) {
		c, store, _, _, _, _ := fixture(t)
		store.apply = func(context.Context, func(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) error) error {
			store.state.Running = detached(store.state.Running)
			store.state.Running.RunningRevision += "_newer"
			return &config.ApplyError{Err: errors.New("forward"), RestoreError: &config.ErrRevisionMismatch{CurrentRevision: "newer"}}
		}
		if _, err := c.Reset(context.Background(), "cas", config.DefaultConfig()); err == nil {
			t.Fatal("expected conflict")
		}
		tick(t, c)
		ready(t, c, true)
		if c.work.snapshot.RunningRevision != store.state.Running.RunningRevision {
			t.Fatal("newer authority overwritten")
		}
	})
}

func TestRefreshAndExplicitReplace(t *testing.T) {
	c, _, engine, _, env, _ := fixture(t)
	tick(t, c)
	old := c.work.admission.ApplyID
	result, err := c.Replay(context.Background(), true)
	if err != nil || env.refreshes != 1 || result.ApplyID == old || env.pcaps != 1 {
		t.Fatalf("refresh: %+v %v", result, err)
	}
	if err := c.Reconcile(context.Background(), protection.SubsystemInterfaces); err != nil {
		t.Fatal(err)
	}
	if engine.count("interfaces-replace") != 1 {
		t.Fatal("explicit replace not sent")
	}
	tick(t, c)
	ready(t, c, true)
	if engine.count("interfaces-replace") != 1 {
		t.Fatal("automatic destructive retry")
	}
}

func TestDisabledBaselineStillSyncsDemo(t *testing.T) {
	c, store, _, _, _, demo := fixture(t)
	store.state.Running.DataPlane.Enforcement = false
	tick(t, c)
	ready(t, c, false)
	synced, reconciles, _ := demo.counts()
	if synced != 1 || reconciles != 1 {
		t.Fatal("disabled enforcement suppressed demo baseline")
	}
}

func TestDrainBeforeTransitionAndShutdown(t *testing.T) {
	c, store, engine, _, _, _ := fixture(t)
	started, finished := make(chan struct{}), make(chan struct{})
	var once sync.Once
	engine.hook = func(ctx context.Context, phase string) error {
		if phase != "interfaces" {
			return nil
		}
		once.Do(func() {
			close(started)
			<-ctx.Done()
			close(finished)
		})
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	<-started
	store.apply = func(context.Context, func(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) error) error {
		select {
		case <-finished:
		default:
			t.Error("transition began before join")
		}
		return errors.New("test transition declined")
	}
	if _, err := c.Change(context.Background(), "cas", config.ChangeCommit, 0); err == nil {
		t.Fatal("expected test decline")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExpiryCancelsEffectsAndRejectsLateProof(t *testing.T) {
	for _, reader := range []bool{false, true} {
		name := "active-effect"
		if reader {
			name = "waiting-store-reader"
		}
		t.Run(name, func(t *testing.T) {
			c, store, engine, _, _, _ := fixture(t)
			store.state.Running.PendingConfirm = &config.PendingConfirm{Deadline: time.Now().Add(time.Hour)}
			tick(t, c)
			started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			block := func(ctx context.Context) error {
				once.Do(func() {
					close(started)
					<-ctx.Done()
					close(canceled)
					<-release // deliberately delayed old completion
				})
				return ctx.Err()
			}
			if reader {
				store.read = block
			} else {
				engine.mu.Lock()
				engine.observation.Outcomes = nil // lose interfaces proof
				engine.mu.Unlock()
				engine.hook = func(ctx context.Context, name string) error {
					if name == "interfaces" {
						return block(ctx)
					}
					return nil
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- c.Run(ctx) }()
			<-started
			c.mu.Lock()
			c.current.deadline = time.Now().Add(-time.Millisecond)
			c.mu.Unlock()
			c.expire()
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("expiry did not cancel within safety bound")
			}
			c.mu.Lock()
			if c.current.input.Coherent {
				t.Error("expired proof remained coherent")
			}
			c.mu.Unlock()
			close(release)
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExpiredGenerationRollsBackOnlyOnce(t *testing.T) {
	c, store, _, _, _, _ := fixture(t)
	store.state.Running.PendingConfirm = &config.PendingConfirm{Deadline: time.Now().Add(-time.Second)}
	tick(t, c)
	ready(t, c, false)
	tick(t, c)
	ready(t, c, true)
	tick(t, c)
	if store.rollbacks != 1 {
		t.Fatalf("duplicate rollback: %d", store.rollbacks)
	}
}
