// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestApplyChangePreservesPreviousPendingAndCanceledCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := DefaultConfig()
	base.System.Hostname = "baseline"
	if err := store.Save(ctx, base); err != nil {
		t.Fatal(err)
	}
	next := DefaultConfig()
	next.System.Hostname = "pending"
	if err := store.SaveCandidate(ctx, next); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitConfirmed(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	pending, err := store.loadPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next.System.Hostname = "failed"
	if err := store.SaveCandidate(ctx, next); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = store.ApplyChange(ctx, ChangeCommitConfirmed, time.Second, func(ctx context.Context, previous, next *Config) error {
		calls++
		if calls == 1 {
			cancel()
			return errors.New("apply failed")
		}
		if ctx.Err() != nil || next.System.Hostname != "pending" {
			t.Fatalf("recovery context/target: %v %s", ctx.Err(), next.System.Hostname)
		}
		return nil
	})
	var failure *ApplyError
	if !errors.As(err, &failure) || failure.RestoreError != nil || failure.ReapplyError != nil || calls != 2 {
		t.Fatalf("apply result: %v calls=%d", err, calls)
	}
	gotPending, err := store.loadPending(context.Background())
	if err != nil || !reflect.DeepEqual(gotPending, pending) || store.pendingTimer == nil {
		t.Fatalf("pending not restored: %+v %v", gotPending, err)
	}
	if err := store.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(context.Background())
	if err != nil || got.System.Hostname != "baseline" {
		t.Fatalf("baseline lost: %+v %v", got, err)
	}
}

func TestApplyChangeReportsRestoreFailure(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Save(ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER deny_restore BEFORE DELETE ON configs WHEN OLD.key = 'running' BEGIN SELECT RAISE(ABORT, 'restore denied'); END`); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = store.ApplyChange(ctx, ChangeCommit, 0, func(context.Context, *Config, *Config) error { calls++; return errors.New("apply failed") })
	var failure *ApplyError
	if !errors.As(err, &failure) || failure.RestoreError == nil || failure.ReapplyError == nil || calls != 1 {
		t.Fatalf("missing recovery failure: %v calls=%d", err, calls)
	}
	fault, err := store.RuntimeApplyFault(ctx)
	if err != nil || fault == "" {
		t.Fatalf("health fault missing: %q %v", fault, err)
	}
}

func TestFailedConfirmedApplyCannotExpireAfterRestoration(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	baseline := DefaultConfig()
	baseline.System.Hostname = "before-apply"
	if err := store.Save(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	next := DefaultConfig()
	next.System.Hostname = "candidate"
	if err := store.SaveCandidate(ctx, next); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = store.ApplyChange(ctx, ChangeCommitConfirmed, time.Millisecond, func(context.Context, *Config, *Config) error {
		calls++
		if calls == 1 {
			time.Sleep(10 * time.Millisecond)
			return errors.New("nft failed")
		}
		return nil
	})
	var failure *ApplyError
	if !errors.As(err, &failure) || failure.RestoreError != nil || failure.ReapplyError != nil {
		t.Fatalf("apply result: %v", err)
	}
	if _, err := store.loadPending(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed confirmed commit retained timer: %v", err)
	}
	time.Sleep(10 * time.Millisecond) // allow any already-fired callback to recheck pending
	running, err := store.Load(ctx)
	if err != nil || running.System.Hostname != baseline.System.Hostname {
		t.Fatalf("running changed after failed apply: %+v %v", running, err)
	}
	candidate, err := store.LoadCandidate(ctx)
	if err != nil || candidate.System.Hostname != "candidate" {
		t.Fatalf("candidate changed: %+v %v", candidate, err)
	}
}

// A transition that fails at runtime from management recovery restores the
// refused running configuration and its boot fault without reapplying it.
func TestApplyChangeFromRecoveryDoesNotReapplyRefusedConfig(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	refused := DefaultConfig()
	refused.System.Hostname = "refused"
	if err := store.Save(ctx, refused); err != nil {
		t.Fatal(err)
	}
	if err := store.SetManagementBootFault(ctx, "refused at boot"); err != nil {
		t.Fatal(err)
	}
	candidate := DefaultConfig()
	candidate.System.Hostname = "candidate"
	if err := store.SaveCandidate(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	var applied []string
	err = store.ApplyChange(ctx, ChangeCommit, 0, func(_ context.Context, _, next *Config) error {
		applied = append(applied, next.System.Hostname)
		return errors.New("apply failed")
	})
	var failure *ApplyError
	if !errors.As(err, &failure) || !failure.Recovery || failure.RestoreError != nil || failure.ReapplyError != nil {
		t.Fatalf("apply result: %v", err)
	}
	if !reflect.DeepEqual(applied, []string{"candidate"}) {
		t.Fatalf("applied %q, want only the candidate", applied)
	}
	if fault, err := store.ManagementBootFault(ctx); err != nil || fault != "refused at boot" {
		t.Fatalf("boot fault = %q, %v", fault, err)
	}
	running, err := store.Load(ctx)
	if err != nil || running.System.Hostname != "refused" {
		t.Fatalf("running = %v, %v", running, err)
	}
}
