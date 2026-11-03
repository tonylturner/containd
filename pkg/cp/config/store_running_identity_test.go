// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func runningState(t *testing.T, s *SQLiteStore) ConfigSnapshot {
	t.Helper()
	snapshot, err := s.ReadSnapshot(context.Background(), SnapshotRunning, true)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertFreshRunning(t *testing.T, before, after ConfigSnapshot) {
	t.Helper()
	if !after.RunningRevision.Valid() || after.RunningRevision == before.RunningRevision {
		t.Fatalf("running identity not fresh: %q -> %q", before.RunningRevision, after.RunningRevision)
	}
}

func TestRunningIdentityWriteInventory(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	base := runningState(t, s)
	if !base.RunningRevision.Valid() {
		t.Fatal("save omitted identity")
	}
	if err := testSaveCandidate(s, ctx, base.Running); err != nil {
		t.Fatal(err)
	}
	candidate := runningState(t, s)
	if candidate.RunningRevision != base.RunningRevision || candidate.Revision == base.Revision {
		t.Fatal("candidate identity/CAS mixed")
	}
	if _, err := Repair(ctx, s, func(c *Config) error {
		if c == nil {
			return errors.New("nil config")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := runningState(t, s); got.RunningRevision != base.RunningRevision {
		t.Fatal("no-op repair minted")
	}
	for _, write := range []struct {
		name string
		run  func() error
	}{
		{"identical recommit", func() error { return testCommitConfirmed(s, ctx, time.Hour) }},
		{"direct identical save", func() error { return s.Save(ctx, runningState(t, s).Running) }},
		{"direct identical IDS save", func() error { return s.SaveIDSRules(ctx, runningState(t, s).Running.IDS.Rules) }},
		{"running repair", func() error {
			_, err := Repair(ctx, s, func(c *Config) error { c.Description = "repaired"; return nil })
			return err
		}},
		{"manual identical rollback", func() error { return testRollback(s, ctx) }},
		{"repeated rollback", func() error { return testRollback(s, ctx) }},
	} {
		t.Run(write.name, func(t *testing.T) {
			before := runningState(t, s)
			if err := write.run(); err != nil {
				t.Fatal(err)
			}
			assertFreshRunning(t, before, runningState(t, s))
		})
	}
	if err := testCommitConfirmed(s, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	pending := runningState(t, s)
	if pending.PendingConfirm == nil {
		t.Fatal("missing coherent pending deadline")
	}
	if err := testConfirmCommit(s, ctx); err != nil {
		t.Fatal(err)
	}
	confirmed := runningState(t, s)
	if confirmed.RunningRevision != pending.RunningRevision || confirmed.PendingConfirm != nil || confirmed.Revision == pending.Revision {
		t.Fatal("confirm minted identity or failed to retire deadline")
	}
	if err := s.CompleteRuntimeApply(ctx, confirmed.RunningRevision, confirmed.Transition.ID); err != nil {
		t.Fatal(err)
	}
	if runningState(t, s).RunningRevision != confirmed.RunningRevision {
		t.Fatal("replay completion minted")
	}
}

func TestRunningIdentityCandidateOnlyRepairAndProvenance(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	before := runningState(t, s)
	if err := testMutateCandidate(s, ctx, func(c *Config) error { c.Description = "candidate"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := Repair(ctx, s, func(c *Config) error {
		if c.Description == "candidate" {
			c.Description = "candidate repaired"
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := runningState(t, s); got.RunningRevision != before.RunningRevision {
		t.Fatal("candidate repair minted running")
	}
	if err := testCommit(s, ctx); err != nil {
		t.Fatal(err)
	}
	previous, err := readRunningIdentity(ctx, s.db, configKeyPrevious)
	if err != nil || previous != before.RunningRevision {
		t.Fatalf("lost previous provenance: %q %v", previous, err)
	}
	if err := testRollback(s, ctx); err != nil {
		t.Fatal(err)
	}
	after := runningState(t, s)
	if after.RunningRevision == previous {
		t.Fatal("rollback reused provenance identity")
	}
}

func TestRunningIdentityGenesisTransactionalAndIdempotent(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	if err := testCommit(s, ctx); err != nil {
		t.Fatal(err)
	}
	markLegacyIdentity(t, s)
	if _, err := s.db.Exec(`CREATE TRIGGER deny_genesis BEFORE INSERT ON running_identity
 WHEN NEW.key = 'previous' BEGIN SELECT RAISE(ABORT, 'genesis denied'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.initializeRunningIdentities(ctx); err == nil {
		t.Fatal("genesis trigger ignored")
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM running_identity`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial genesis: %d %v", count, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER deny_genesis`); err != nil {
		t.Fatal(err)
	}
	if err := s.initializeRunningIdentities(ctx); err != nil {
		t.Fatal(err)
	}
	before := runningState(t, s)
	previous, err := readRunningIdentity(ctx, s.db, configKeyPrevious)
	if err != nil || !previous.Valid() {
		t.Fatal(err)
	}
	s = reopenSnapshotStore(t, s)
	after := runningState(t, s)
	if after.RunningRevision != before.RunningRevision || after.Revision != before.Revision {
		t.Fatal("unchanged open reminted")
	}
	gotPrevious, err := readRunningIdentity(ctx, s.db, configKeyPrevious)
	if err != nil || gotPrevious != previous {
		t.Fatal("previous identity changed on open")
	}
}

func TestRunningIdentityCorruptionIsNotGenesis(t *testing.T) {
	for _, corrupt := range []string{
		`DELETE FROM running_identity WHERE key = 'running'`,
		`UPDATE running_identity SET token = 'recovery:invalid' WHERE key = 'running'`,
	} {
		t.Run(corrupt, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.db")
			s, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot := runningState(t, s); snapshot.Running != nil || snapshot.RunningRevision != "" {
				t.Fatal("empty store manufactured desired identity")
			}
			if err := s.Save(context.Background(), DefaultConfig()); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(corrupt); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ReadSnapshot(context.Background(), SnapshotRunning, true); err == nil {
				t.Fatal("read ignored corruption")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if opened, err := NewSQLiteStore(path); err == nil {
				opened.Close()
				t.Fatal("open silently repaired missing/malformed identity")
			}
		})
	}
}
