// SPDX-License-Identifier: Apache-2.0

package convergence

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestRecoveredProjectionNeedsFreshAttempt(t *testing.T) {
	c, store, engine, local, _, _ := fixture(t)
	store.state.Running.Services.Proxy.Forward.Enabled = true
	store.state.Running.Services.Proxy.Forward.ListenPort = 3128
	local.quarantine = true
	local.failed = protection.SubsystemForwardProxy
	tick(t, c)
	old := c.work.admission.Metadata
	oldRules := c.work.rules
	local.mu.Lock()
	local.quarantine, local.failed = false, ""
	local.mu.Unlock()
	tick(t, c)
	if c.work.admission.ApplyID == old.ApplyID || c.work.admission.PreviousApplyID != old.ApplyID {
		t.Fatal("recovered policy reused narrowed attempt or lost predecessor")
	}
	if len(c.work.rules.LocalInput) <= len(oldRules.LocalInput) || engine.count("nft") != 2 {
		t.Fatal("recovered local INPUT not installed")
	}
	ready(t, c, true)
}

func TestUnknownAndOriginalFaultsNeverBecomeReady(t *testing.T) {
	t.Run("missing-telemetry", func(t *testing.T) {
		c, _, engine, _, _, _ := fixture(t)
		tick(t, c)
		engine.mu.Lock()
		engine.observation.Engine.ObservedAt = time.Time{}
		engine.mu.Unlock()
		ready(t, c, false)
	})
	t.Run("wireguard-quarantine", func(t *testing.T) {
		c, store, _, _, _, _ := fixture(t)
		store.state.Running.Services.VPN.WireGuard.Enabled = true
		store.state.Running.Services.VPN.WireGuard.ListenInterfaces = []string{"missing"}
		tick(t, c)
		got := ready(t, c, false)
		found := false
		for _, o := range got.Subsystems {
			if o.Name == protection.SubsystemWireGuard {
				found = o.Required && o.State == protection.DeliveryFailed && !o.Retryable && o.Acknowledged == nil
			}
		}
		if !found {
			t.Fatal("quarantined engine service erased desired obligation")
		}
	})
	t.Run("lost-nft-proof", func(t *testing.T) {
		c, _, engine, _, _, _ := fixture(t)
		tick(t, c)
		engine.mu.Lock()
		engine.observation.Engine.Installed = nil
		for i, o := range engine.observation.Outcomes {
			if o.Name == protection.SubsystemNFT {
				engine.observation.Outcomes[i].Acknowledged = nil
			}
		}
		engine.mu.Unlock()
		ready(t, c, false)
		tick(t, c)
		ready(t, c, true)
		if engine.count("nft") != 2 || engine.count("interfaces") != 1 {
			t.Fatal("lost policy proof did not select nft alone")
		}
	})
}

func TestChangedEngineInputRenewsAttempt(t *testing.T) {
	c, _, engine, _, _, _ := fixture(t)
	changed := true
	engine.hook = func(_ context.Context, name string) error {
		if changed && name == "routing" {
			return ErrInputChanged
		}
		return nil
	}
	if err := c.Tick(context.Background()); !errors.Is(err, ErrInputChanged) {
		t.Fatalf("changed input: %v", err)
	}
	old := c.work.admission.ApplyID
	changed = false
	tick(t, c)
	if c.work.admission.ApplyID == old {
		t.Fatal("changed resolved phase reused metadata")
	}
	ready(t, c, true)
}

func TestConfirmRetiresDeadlineWithoutReplay(t *testing.T) {
	c, store, engine, _, _, _ := fixture(t)
	store.state.Running.PendingConfirm = &config.PendingConfirm{Deadline: time.Now().Add(time.Minute)}
	tick(t, c)
	first := c.work.admission
	if _, err := c.Confirm(context.Background(), store.state.Revision); err != nil {
		t.Fatal(err)
	}
	tick(t, c)
	c.expire()
	if c.work.admission != first || engine.count("nft") != 1 {
		t.Fatal("confirm replayed running")
	}
	c.mu.Lock()
	deadline := c.current.deadline
	c.mu.Unlock()
	if !deadline.IsZero() {
		t.Fatal("old confirmation timer survived")
	}
	ready(t, c, true)
}

func TestTrustWriteAndRetryAreNotGuardResolution(t *testing.T) {
	c, store, engine, _, _, _ := fixture(t)
	tick(t, c)
	first := c.work.admission
	writes := 0
	result, err := c.TrustChanged(context.Background(), func(_ context.Context, s *config.RunningSnapshot) error {
		writes++
		if s.RunningRevision != store.state.Running.RunningRevision {
			t.Fatal("trust write used stale running")
		}
		return nil
	})
	if err != nil || writes != 1 || result.ApplyID == first.ApplyID || result.RunningRevision != config.RunningRevision(first.RunningRevision) {
		t.Fatalf("trust write: %+v %v", result, err)
	}
	completes := store.completes
	store.state.Transition = &config.TransitionGuard{ID: "uncertain", State: config.TransitionUncompleted,
		RunningRevision: store.state.Running.RunningRevision}
	tick(t, c)
	ready(t, c, false)
	if store.completes != completes {
		t.Fatal("trust/retry resolved blocked guard")
	}
	if engine.count("config") != 3 {
		t.Fatal("recovery not applied")
	}
}

func TestFailedResolutionReentersRecoverySynchronously(t *testing.T) {
	c, store, engine, _, _, _ := fixture(t)
	store.apply = func(context.Context, func(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) error) error {
		store.state.Transition = &config.TransitionGuard{ID: "blocked", State: config.TransitionBlocked,
			RunningRevision: store.state.Running.RunningRevision}
		return &config.ApplyError{Err: errors.New("rejected transition"), Recovery: true}
	}
	_, err := c.Change(context.Background(), store.state.Revision, config.ChangeCommit, 0)
	var failure *config.ApplyError
	if !errors.As(err, &failure) || failure.ReapplyError != nil {
		t.Fatalf("recovery compensation: %v", err)
	}
	if engine.count("nft") != 1 || c.work.admission.Mode != protection.ModeRecovery {
		t.Fatal("returned before fail-closed recovery delivery")
	}
	ready(t, c, false)
}

func TestPersistedReplayFaultClearsOnlyAfterBaseline(t *testing.T) {
	c, store, engine, _, _, _ := fixture(t)
	store.fault = "earlier replay failed"
	ready(t, c, false)
	engine.fail["nft"] = 1
	if err := c.Tick(context.Background()); err == nil {
		t.Fatal("critical failure accepted")
	}
	if store.fault == "" {
		t.Fatal("failed replay cleared durable fault")
	}
	tick(t, c)
	ready(t, c, true)
	if store.fault != "" {
		t.Fatal("verified baseline did not clear replay fault")
	}
	completes := store.completes
	tick(t, c)
	if store.completes != completes {
		t.Fatal("healthy polling rewrote runtime metadata")
	}
}

func TestRecoveryOverrideRevokesReadinessBeforePoll(t *testing.T) {
	c, _, _, _, env, _ := fixture(t)
	tick(t, c)
	ready(t, c, true)
	env.mu.Lock()
	env.recovery = true
	env.mu.Unlock()
	ready(t, c, false)
}

func TestDHCPRenderingFaultIsVisibleButPlaceholderIsNotProof(t *testing.T) {
	m := protection.Metadata{BootID: "boot", ApplyID: "apply", RunningRevision: "running", Mode: protection.ModeNormal}
	engine := proof(m, protection.SubsystemDHCP, protection.OwnerEngine, false)
	local := protection.OwnerOutcome{Name: protection.SubsystemDHCP, Owner: protection.OwnerEngine,
		DesiredRevision: m.RunningRevision, State: protection.DeliveryPending}
	got := collect([]protection.OwnerOutcome{local}, []protection.OwnerOutcome{engine}, nil)
	if len(got) != 1 || got[0].Acknowledged == nil {
		t.Fatal("render placeholder erased actual engine proof")
	}
	local.Fault = &protection.Fault{Kind: protection.FaultRender, Reason: "DHCP render rejected"}
	local.State = protection.DeliveryFailed
	got = collect([]protection.OwnerOutcome{local}, []protection.OwnerOutcome{engine}, nil)
	if len(got) != 1 || got[0].Fault == nil || got[0].Acknowledged != nil {
		t.Fatal("DHCP render fault was hidden")
	}
}

func TestInvalidPolicyCannotRefreshRuntimeMaterial(t *testing.T) {
	c, store, _, _, env, _ := fixture(t)
	store.state.Running.Firewall.DefaultAction = "invalid"
	if _, err := c.Replay(context.Background(), true); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if env.refreshes != 0 {
		t.Fatal("runtime material refreshed before policy preflight")
	}
}

// Use the real runtime store here: the callback's compensation metadata,
// cancellation isolation and guard completion are not just fake conventions.
func TestSQLiteTransitionAndCompensationBudgets(t *testing.T) {
	c, _, engine, _, _, _ := fixture(t)
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	cfg := config.DefaultConfig()
	cfg.DataPlane.Enforcement = true
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReadRunning(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original := state.Running.RunningRevision
	if _, err := store.SaveCandidate(ctx, state.Revision, cfg); err != nil {
		t.Fatal(err)
	}
	state, err = store.ReadRunning(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.options.Store = store
	engine.fail["nft"] = 1
	var seen []protection.Revision
	engine.hook = func(ctx context.Context, name string) error {
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > ApplyBudget {
			t.Error("effect lacks bounded forward/compensation context")
		}
		if name == "nft" {
			engine.mu.Lock()
			seen = append(seen, engine.observation.Engine.RunningRevision)
			engine.mu.Unlock()
		}
		return nil
	}
	_, err = c.Change(ctx, state.Revision, config.ChangeCommitConfirmed, time.Minute)
	var failure *config.ApplyError
	if !errors.As(err, &failure) || failure.RestoreError != nil || failure.ReapplyError != nil {
		t.Fatalf("real compensation: %v", err)
	}
	after, err := store.ReadRunning(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Running.RunningRevision == original || after.Transition != nil || len(seen) != 2 || seen[0] == seen[1] {
		t.Fatalf("restored authority reused/uncertain: %+v %v", after, seen)
	}
	// The next retry has its own total five-second budget.
	engine.hook = func(ctx context.Context, _ string) error {
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > RetryBudget {
			t.Error("background effect exceeds five-second total budget")
		}
		return nil
	}
	tick(t, c)
	ready(t, c, true)
}
