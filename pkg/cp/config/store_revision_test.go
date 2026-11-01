// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func revisionSnapshot(t *testing.T, s *SQLiteStore) ConfigSnapshot {
	t.Helper()
	snapshot, err := s.ReadSnapshot(context.Background(), SnapshotPair, true)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Revision.Valid() {
		t.Fatalf("invalid revision %q", snapshot.Revision)
	}
	return snapshot
}

func TestRevisionCompetingSavesAcrossHandles(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.db")
	left, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	if err := left.Save(ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	right, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()
	base := revisionSnapshot(t, left).Revision
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i, store := range []*SQLiteStore{left, right} {
		wg.Go(func() {
			<-start
			cfg := DefaultConfig()
			cfg.Description = fmt.Sprint(i)
			_, err := store.SaveCandidate(ctx, base, cfg)
			results <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		var mismatch *ErrRevisionMismatch
		switch {
		case err == nil:
			success++
		case errors.As(err, &mismatch):
			conflicts++
			if mismatch.CurrentRevision != revisionSnapshot(t, left).Revision {
				t.Fatal("mismatch did not return the locked authority")
			}
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflicts=%d", success, conflicts)
	}
}

func TestRevisionRejectsWithoutEffects(t *testing.T) {
	ctx := context.Background()
	s := candidateStore(t)
	base := revisionSnapshot(t, s)
	current, err := s.MutateCandidate(ctx, base.Revision, func(c *Config) error {
		c.Description = "newer"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func() error{
		func() error {
			_, err := s.MutateCandidate(ctx, base.Revision, func(*Config) error { t.Fatal("stale callback ran"); return nil })
			return err
		},
		func() error { _, err := s.SaveCandidate(ctx, base.Revision, DefaultConfig()); return err },
		func() error { _, err := s.Commit(ctx, base.Revision); return err },
		func() error { _, err := s.CommitConfirmed(ctx, base.Revision, time.Hour); return err },
		func() error { _, err := s.ConfirmCommit(ctx, base.Revision); return err },
		func() error { _, err := s.Rollback(ctx, base.Revision); return err },
		func() error {
			_, err := s.ApplyChange(ctx, base.Revision, ChangeCommit, 0, func(context.Context, *Config, *Config) error {
				t.Fatal("stale runtime apply ran")
				return nil
			})
			return err
		},
		func() error {
			_, err := s.ApplyReset(ctx, base.Revision, DefaultConfig(), func(context.Context, *Config, *Config) error {
				t.Fatal("stale reset apply ran")
				return nil
			})
			return err
		},
	} {
		var mismatch *ErrRevisionMismatch
		if err := mutate(); !errors.As(err, &mismatch) || mismatch.CurrentRevision != current {
			t.Fatalf("expected mismatch, got %v", err)
		}
		after := revisionSnapshot(t, s)
		if after.Revision != current || after.Candidate.Description != "newer" || s.pendingTimer != nil {
			t.Fatal("rejected CAS changed state")
		}
	}
	if _, err := s.MutateCandidate(ctx, current, func(c *Config) error {
		c.Firewall.DefaultAction = "invalid"
		return nil
	}); err == nil {
		t.Fatal("invalid edit accepted")
	}
	if revisionSnapshot(t, s).Revision != current {
		t.Fatal("validation failure allocated")
	}
}

func TestRevisionInternalTransitionsAndNoABA(t *testing.T) {
	ctx := context.Background()
	s := candidateStore(t)
	seen := map[Revision]bool{}
	remember := func() {
		t.Helper()
		revision := revisionSnapshot(t, s).Revision
		if seen[revision] {
			t.Fatalf("reused %s", revision)
		}
		seen[revision] = true
	}
	remember()
	before := revisionSnapshot(t, s).Revision
	if _, err := Repair(ctx, s, func(*Config) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if revisionSnapshot(t, s).Revision != before {
		t.Fatal("no-op repair allocated")
	}
	if err := s.SetRuntimeApplyFault(ctx, "diagnostic"); err != nil {
		t.Fatal(err)
	}
	if revisionSnapshot(t, s).Revision != before {
		t.Fatal("fault bookkeeping allocated")
	}
	for _, edit := range []func(*Config){
		func(c *Config) { c.Services.VPN.WireGuard.PrivateKey = "new secret" },
		func(c *Config) { c.IDS.Rules = []IDSRule{} },
	} {
		cfg := revisionSnapshot(t, s).Candidate
		edit(cfg)
		if _, err := s.SaveCandidate(ctx, revisionSnapshot(t, s).Revision, cfg); err != nil {
			t.Fatal(err)
		}
		remember()
	}
	if err := testCommitConfirmed(s, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	remember()
	oldPending := revisionSnapshot(t, s).Revision
	if err := testCommitConfirmed(s, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	remember()
	if _, err := s.ConfirmCommit(ctx, oldPending); err == nil {
		t.Fatal("stale confirm accepted newer pending commit")
	}
	if s.pendingTimer == nil {
		t.Fatal("stale confirm stopped the newer timer")
	}
	if err := testRollback(s, ctx); err != nil {
		t.Fatal(err)
	}
	remember()
	if err := testApplyChange(s, ctx, ChangeCommit, 0, func(context.Context, *Config, *Config) error {
		return errors.New("runtime failure")
	}); err == nil {
		t.Fatal("apply failure hidden")
	}
	remember()
	if err := testApplyReset(s, ctx, DefaultConfig(), func(context.Context, *Config, *Config) error { return nil }); err != nil {
		t.Fatal(err)
	}
	remember()
	if err := s.SaveIDSRules(ctx, nil); err != nil {
		t.Fatal(err)
	}
	remember()
	if err := s.WipeAll(ctx); err != nil {
		t.Fatal(err)
	}
	remember()
}

func TestRevisionExistingDatabaseAndReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE configs (key TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	base := revisionSnapshot(t, store).Revision
	if err := store.Save(ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	current := revisionSnapshot(t, store).Revision
	if current == base {
		t.Fatal("save did not allocate")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if revisionSnapshot(t, store).Revision != current {
		t.Fatal("reopen allocated without a migration")
	}
	if _, err := store.SaveCandidate(ctx, base, DefaultConfig()); err == nil {
		t.Fatal("reopen accepted old revision")
	}
}

func TestRevisionCompensationDoesNotOverwriteAnotherHandle(t *testing.T) {
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
	var concurrent Revision
	_, err = first.ApplyChange(ctx, revisionSnapshot(t, first).Revision, ChangeCommit, 0, func(context.Context, *Config, *Config) error {
		base := revisionSnapshot(t, second)
		cfg := base.Candidate
		cfg.Description = "newer candidate from another handle"
		var saveErr error
		concurrent, saveErr = second.SaveCandidate(ctx, base.Revision, cfg)
		if saveErr != nil {
			t.Fatal(saveErr)
		}
		return errors.New("runtime apply failed")
	})
	var failure *ApplyError
	var mismatch *ErrRevisionMismatch
	if !errors.As(err, &failure) || !errors.As(failure.RestoreError, &mismatch) {
		t.Fatalf("compensation should refuse a superseded state: %v", err)
	}
	after := revisionSnapshot(t, second)
	if after.Revision != concurrent || after.Candidate.Description != "newer candidate from another handle" {
		t.Fatal("compensation overwrote another handle")
	}
}

func TestRevisionMigrationDoesNotEditCurrentSnapshots(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "existing.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	before := revisionSnapshot(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// Model a current-schema database made before revision metadata existed.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE config_revision`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	after := revisionSnapshot(t, store)
	var counter int64
	if err := store.db.QueryRow(`SELECT counter FROM config_revision WHERE id = 1`).Scan(&counter); err != nil {
		t.Fatal(err)
	}
	if counter != 1 || !reflect.DeepEqual(before.Running, after.Running) || !reflect.DeepEqual(before.Candidate, after.Candidate) {
		t.Fatal("revision metadata migration manufactured a config edit")
	}
}
