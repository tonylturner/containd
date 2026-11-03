// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRunningIdentityCompensationOutcomes(t *testing.T) {
	for _, reapplyFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "restored", true: "reapply pending"}[reapplyFails], func(t *testing.T) {
			s := resetTestStore(t)
			ctx := context.Background()
			before := runningState(t, s)
			var proposed, restored RunningRevision
			var deadline *PendingConfirm
			calls := 0
			err := testApplyReset(s, ctx, DefaultConfig(), func(ctx context.Context, old, next *RunningSnapshot) error {
				calls++
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("effect has no deadline")
				}
				if calls == 1 {
					if old.RunningRevision != before.RunningRevision {
						t.Fatal("previous snapshot is unlabelled")
					}
					proposed = next.RunningRevision
					if !proposed.Valid() || proposed == before.RunningRevision {
						t.Fatal("reset did not mint a fresh running identity")
					}
					return errors.New("partial owner mutation")
				}
				restored, deadline = next.RunningRevision, next.PendingConfirm
				if old.RunningRevision != proposed || next.Config.System.Hostname != "running" ||
					restored == proposed || restored == before.RunningRevision {
					t.Fatal("old owner success is reusable after partial mutation")
				}
				if reapplyFails {
					return errors.New("restored owner still unavailable")
				}
				return nil
			})
			var failure *ApplyError
			if !errors.As(err, &failure) || failure.RestoreError != nil ||
				(failure.ReapplyError != nil) != reapplyFails || failure.HealthError != nil || calls != 2 {
				t.Fatalf("incorrect compensation outcome: %v calls=%d", err, calls)
			}
			after := runningState(t, s)
			assertFreshRunning(t, before, after)
			if after.RunningRevision != restored || deadline == nil || *deadline != *before.PendingConfirm ||
				*after.PendingConfirm != *before.PendingConfirm {
				t.Fatal("restoration lost labelled target or original deadline")
			}
			if reapplyFails {
				if after.Transition == nil || after.Transition.State != TransitionReapplyPending ||
					after.Transition.RunningRevision != restored {
					t.Fatal("restored target not durably replayable")
				}
				s = reopenSnapshotStore(t, s)
				pending := runningState(t, s)
				if pending.Transition == nil || *pending.Transition != *after.Transition || pending.RunningRevision != restored {
					t.Fatal("restart lost restoration outcome")
				}
				if err := s.CompleteRuntimeApply(ctx, restored, pending.Transition.ID); err != nil {
					t.Fatal(err)
				}
			}
			if runningState(t, s).Transition != nil {
				t.Fatal("verified completion retained uncertainty")
			}
		})
	}
}

func TestTransitionGuardCrashAfterResetAndExplicitResolution(t *testing.T) {
	s := resetTestStore(t)
	ctx := context.Background()
	before := runningState(t, s)
	// Commit precisely the transaction a process can leave behind when it dies
	// before effects. No in-memory recovery rows survive the following reopen.
	s.mu.Lock()
	_, err := s.resetLocked(ctx, before.Revision, DefaultConfig(), func(*sql.Tx) error { return nil })
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	s = reopenSnapshotStore(t, s)
	crashed := runningState(t, s)
	if crashed.Transition == nil || crashed.Transition.State != TransitionUncompleted {
		t.Fatal("crash uncertainty was not durable")
	}
	if _, err := loadKindFrom(ctx, s.db, configKeyPrevious); !errors.Is(err, ErrNotFound) {
		t.Fatal("test did not delete reset history")
	}
	if err := s.SetRuntimeApplyFault(ctx, crashed.RunningRevision, ""); !errors.Is(err, ErrTransitionMismatch) {
		t.Fatal(err)
	}
	if err := s.CompleteRuntimeApply(ctx, crashed.RunningRevision, crashed.Transition.ID); !errors.Is(err, ErrTransitionMismatch) {
		t.Fatal("blind replay resolved interrupted transition", err)
	}
	// Even a low-level wipe cannot erase the durable uncertainty marker.
	if err := s.WipeAll(ctx); err != nil {
		t.Fatal(err)
	}
	s = reopenSnapshotStore(t, s)
	if got := runningState(t, s); got.Running != nil || got.Transition == nil || *got.Transition != *crashed.Transition {
		t.Fatal("wipe erased uncertainty")
	}
	if err := testApplyReset(s, ctx, DefaultConfig(), func(context.Context, *RunningSnapshot, *RunningSnapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	resolved := runningState(t, s)
	if resolved.Transition != nil || !resolved.RunningRevision.Valid() || resolved.RunningRevision == crashed.RunningRevision {
		t.Fatal("explicit validated resolution failed")
	}
}

func TestTransitionGuardRestoreFailureSurvivesResetRestart(t *testing.T) {
	s := resetTestStore(t)
	ctx := context.Background()
	before := runningState(t, s)
	calls := 0
	err := testApplyReset(s, ctx, DefaultConfig(), func(context.Context, *RunningSnapshot, *RunningSnapshot) error {
		calls++
		// The reset has already deleted history; reject its compensating
		// restoration transaction, not the reset transaction itself.
		if _, err := s.db.Exec(`CREATE TRIGGER deny_restore BEFORE DELETE ON configs
 WHEN OLD.key = 'running' BEGIN SELECT RAISE(ABORT, 'restore denied'); END`); err != nil {
			t.Fatal(err)
		}
		return errors.New("rules rejected")
	})
	var failure *ApplyError
	if !errors.As(err, &failure) || failure.RestoreError == nil || failure.ReapplyError == nil || calls != 1 {
		t.Fatal("restore/reapply outcomes conflated", err)
	}
	failed := runningState(t, s)
	assertFreshRunning(t, before, failed)
	if failed.Transition == nil || failed.Transition.State != TransitionBlocked {
		t.Fatal("restore failure was not durably blocked")
	}
	s = reopenSnapshotStore(t, s)
	restarted := runningState(t, s)
	if restarted.Transition == nil || *restarted.Transition != *failed.Transition {
		t.Fatal("restart forgot failed restoration")
	}
	if err := s.CompleteRuntimeApply(ctx, restarted.RunningRevision, restarted.Transition.ID); !errors.Is(err, ErrTransitionMismatch) {
		t.Fatal("normal replay accepted rejected reset")
	}
}

func TestTransitionGuardNewerAuthorityAndStaleCompletions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.db")
	first, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.Save(ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	second, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var oldGuard *TransitionGuard
	var authority ConfigSnapshot
	_, err = first.ApplyChange(ctx, runningState(t, first).Revision, ChangeCommit, 0,
		func(context.Context, *RunningSnapshot, *RunningSnapshot) error {
			oldGuard = runningState(t, second).Transition
			// A separate handle may take authority even while this callback is
			// active. Its pending guard must not be cleared or faulted by us.
			if err := testCommit(second, ctx); err != nil {
				t.Fatal(err)
			}
			authority = runningState(t, second)
			return nil
		})
	var failure *ApplyError
	var mismatch *ErrRevisionMismatch
	if !errors.As(err, &failure) || !errors.As(failure.RestoreError, &mismatch) {
		t.Fatal("old completion did not adopt newer-authority outcome", err)
	}
	after := runningState(t, second)
	if after.RunningRevision != authority.RunningRevision || after.Transition == nil ||
		*after.Transition != *authority.Transition {
		t.Fatal("stale apply altered newer authority")
	}
	if fault, err := second.RuntimeApplyFault(ctx); err != nil || fault != "" {
		t.Fatal("old fault attached to newer authority", fault, err)
	}
	if err := second.CompleteRuntimeApply(ctx, oldGuard.RunningRevision, oldGuard.ID); !errors.Is(err, ErrTransitionMismatch) {
		t.Fatal("stale completion cleared newer guard", err)
	}
	if err := second.SetRuntimeApplyFault(ctx, oldGuard.RunningRevision, "stale fault"); !errors.Is(err, ErrTransitionMismatch) {
		t.Fatal("stale diagnostic attached to newer authority", err)
	}
	if err := second.CompleteRuntimeApply(ctx, after.RunningRevision, after.Transition.ID); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionGuardClearFailureRemainsUncertain(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	if _, err := s.db.Exec(`CREATE TRIGGER deny_clear BEFORE DELETE ON runtime_transition
 BEGIN SELECT RAISE(ABORT, 'clear denied'); END`); err != nil {
		t.Fatal(err)
	}
	err := testApplyChange(s, ctx, ChangeCommit, 0, func(context.Context, *RunningSnapshot, *RunningSnapshot) error { return nil })
	var failure *ApplyError
	if !errors.As(err, &failure) || failure.RestoreError != nil || failure.ReapplyError != nil || failure.HealthError == nil {
		t.Fatal("failed durable completion invented certainty", err)
	}
	if state := runningState(t, s); state.Transition == nil || state.Transition.State != TransitionReapplyPending {
		t.Fatal("health persistence failure lost guard")
	}
}

func TestTransitionEffectsReleaseStoreLockAndExpiryCoalesces(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	notify := make(chan struct{}, 1)
	s.SetStoreNotify(notify)
	s.SetAutoRollbackNotify(notify)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var releaseOnce sync.Once
	releaseApply := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() { releaseApply(); <-done })
	base := testBaseRevision(s, ctx)
	go func() {
		_, err := s.ApplyChange(ctx, base, ChangeCommitConfirmed, 20*time.Millisecond,
			func(_ context.Context, _, next *RunningSnapshot) error {
				if next.PendingConfirm == nil {
					return errors.New("callback missing deadline")
				}
				close(entered)
				<-release
				return nil
			})
		done <- err
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("apply did not start")
	}
	// Reads and nonblocking notifications remain available during effects.
	read := make(chan ConfigSnapshot, 1)
	go func() {
		snapshot, _ := s.ReadSnapshot(ctx, SnapshotRunning, true)
		read <- snapshot
	}()
	var applying ConfigSnapshot
	select {
	case applying = <-read:
	case <-time.After(time.Second):
		releaseApply()
		<-done
		t.Fatal("runtime effect held store lock")
	}
	if applying.PendingConfirm == nil || applying.Transition == nil || applying.Transition.State != TransitionUncompleted {
		t.Fatal("incoherent transition read")
	}
	time.Sleep(40 * time.Millisecond)
	// The timer waits for the synchronous transition gate, not mu. It must
	// not roll back halfway through a forward callback.
	if got := runningState(t, s); got.RunningRevision != applying.RunningRevision {
		t.Fatal("expiry overlapped active synchronous effect")
	}
	releaseApply()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	var expired ConfigSnapshot
	for {
		expired = runningState(t, s)
		if expired.PendingConfirm == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expiry was not bounded")
		}
		time.Sleep(time.Millisecond)
	}
	assertFreshRunning(t, applying, expired)
	if expired.Transition == nil || expired.Transition.State != TransitionReapplyPending {
		t.Fatal("expiry failed to request restored-generation replay")
	}
	if err := s.CompleteRuntimeApply(ctx, applying.RunningRevision, applying.Transition.ID); !errors.Is(err, ErrTransitionMismatch) {
		t.Fatal("late pre-expiry success accepted")
	}
	// A waiting stale timer must coalesce against the now absent pending row.
	s.mu.Lock()
	applied, err := s.timedRollbackLocked(ctx)
	s.mu.Unlock()
	if err != nil || applied || runningState(t, s).RunningRevision != expired.RunningRevision {
		t.Fatal("expiry minted twice", err)
	}
}

func TestStoreNotificationNeverBlocksWithoutReceiver(t *testing.T) {
	s := candidateStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.SetStoreNotify(make(chan struct{}))
	if err := s.Save(ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionGuardMustPersistBeforeEffects(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	before := runningState(t, s)
	if _, err := s.db.Exec(`CREATE TRIGGER deny_guard BEFORE INSERT ON runtime_transition
 BEGIN SELECT RAISE(ABORT, 'guard denied'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := s.ApplyChange(ctx, before.Revision, ChangeCommitConfirmed, time.Hour,
		func(context.Context, *RunningSnapshot, *RunningSnapshot) error {
			t.Fatal("unguarded transition reached effects")
			return nil
		})
	if err == nil {
		t.Fatal("guard persistence failure ignored")
	}
	after := runningState(t, s)
	if after.Revision != before.Revision || after.RunningRevision != before.RunningRevision ||
		after.PendingConfirm != nil || after.Transition != nil {
		t.Fatal("rejected guard transaction changed authority")
	}
}

func TestTransitionReadRunningIsDetachedAndCoherent(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	if err := testCommitConfirmed(s, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	state, err := s.ReadRunning(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Running == nil || state.Transition == nil || state.Revision != state.Transition.Revision ||
		state.Running.RunningRevision != state.Transition.RunningRevision || state.Running.PendingConfirm == nil {
		t.Fatal("coordinator read omitted generation, deadline or guard")
	}
	deadline := state.Running.PendingConfirm.Deadline
	token := state.Running.RunningRevision
	state.Running.Config.Description = "only a detached edit"
	state.Running.PendingConfirm.Deadline = time.Time{}
	state.Transition.State = TransitionBlocked
	again, err := s.ReadRunning(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Running.Config.Description == state.Running.Config.Description ||
		again.Running.PendingConfirm.Deadline != deadline || again.Transition.State != TransitionReapplyPending ||
		again.Running.RunningRevision != token {
		t.Fatal("coordinator read aliased persistence")
	}
}

func TestTransitionEmptyStoreRestoration(t *testing.T) {
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.SaveIDSRules(ctx, DefaultIDSConfig().Rules[:1]); err != nil {
		t.Fatal(err)
	}
	if state := runningState(t, s); state.Running != nil || state.RunningRevision != "" {
		t.Fatal("standalone IDS bank manufactured desired config")
	}
	err = testApplyReset(s, ctx, DefaultConfig(), func(context.Context, *RunningSnapshot, *RunningSnapshot) error {
		return errors.New("failed initial apply")
	})
	var failure *ApplyError
	if !errors.As(err, &failure) || failure.RestoreError != nil || failure.ReapplyError == nil || failure.HealthError != nil {
		t.Fatal("empty-store restoration outcome conflated", err)
	}
	after := runningState(t, s)
	if after.Running != nil || after.Transition == nil || after.Transition.State != TransitionBlocked {
		t.Fatal("empty restored authority not blocked")
	}
	if fault, err := s.RuntimeApplyFault(ctx); err != nil || fault == "" {
		t.Fatal("empty-store restoration lost diagnostics", fault, err)
	}
}
