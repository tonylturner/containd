// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestRunningIdentityRepresentationMigrationPreservesBothTokens(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	if err := testCommit(s, ctx); err != nil {
		t.Fatal(err)
	}
	tokens := map[string]RunningRevision{}
	for _, key := range []string{configKeyRunning, configKeyPrevious} {
		var err error
		tokens[key], err = readRunningIdentity(ctx, s.db, key)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := loadKindFrom(ctx, s.db, key)
		if err != nil {
			t.Fatal(err)
		}
		// The complete decoded config and bank are unchanged; only their
		// embedding/reference representation differs.
		blob, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`UPDATE configs SET data = ? WHERE key = ?`, string(blob), key); err != nil {
			t.Fatal(err)
		}
	}
	s = reopenSnapshotStore(t, s)
	for key, before := range tokens {
		after, err := readRunningIdentity(ctx, s.db, key)
		if err != nil || after != before {
			t.Fatalf("representation migration reminted %s: %q -> %q %v", key, before, after, err)
		}
	}
}

func TestRunningIdentityContentMigrationAndRollback(t *testing.T) {
	for _, mode := range []string{"manual", "expiry", "lazy previous"} {
		t.Run(mode, func(t *testing.T) {
			s := candidateStore(t)
			ctx := context.Background()
			installOrderedLegacyBanks(t, s, nil)
			before := map[string]RunningRevision{}
			for _, key := range []string{configKeyRunning, configKeyPrevious} {
				var err error
				before[key], err = readRunningIdentity(ctx, s.db, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "expiry" {
				blob, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(-time.Hour).UnixNano()})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(`INSERT INTO configs VALUES (?, ?, 0)`, configKeyPending, string(blob)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "lazy previous" {
				if err := testRollback(s, ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				s = reopenSnapshotStore(t, s)
			}
			previous, err := readRunningIdentity(ctx, s.db, configKeyPrevious)
			if err != nil || previous == before[configKeyPrevious] {
				t.Fatal("previous content migration reused token", err)
			}
			migrated := runningState(t, s)
			assertFreshRunning(t, ConfigSnapshot{RunningRevision: before[configKeyRunning]}, migrated)
			if mode == "manual" {
				// An unchanged restart must preserve both migrated tokens before
				// installing previous under a distinct rollback generation.
				s = reopenSnapshotStore(t, s)
				if got := runningState(t, s); got.RunningRevision != migrated.RunningRevision {
					t.Fatal("restart reminted migrated document")
				}
				if err := testRollback(s, ctx); err != nil {
					t.Fatal(err)
				}
			}
			after := runningState(t, s)
			if after.Running.System.Hostname != configKeyPrevious || after.RunningRevision == previous ||
				after.RunningRevision == before[configKeyPrevious] || after.Running.SchemaVersion != SchemaVersionCurrent {
				t.Fatal("rollback did not install migrated previous with fresh identity")
			}
			s = reopenSnapshotStore(t, s)
			if got := runningState(t, s); got.RunningRevision != after.RunningRevision {
				t.Fatal("restart reminted rollback")
			}
		})
	}
}

func TestRunningIdentityCandidateMigrationDoesNotMint(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	if err := testSaveCandidate(s, ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	before := runningState(t, s)
	if _, err := s.db.Exec(`UPDATE configs SET data = json_set(data, '$.schema_version', '0.1.8')
 WHERE key = ?`, configKeyCandidate); err != nil {
		t.Fatal(err)
	}
	s = reopenSnapshotStore(t, s)
	after := runningState(t, s)
	if after.RunningRevision != before.RunningRevision || after.Revision == before.Revision {
		t.Fatal("candidate content migration mixed running identity and CAS")
	}
}

func TestRunningIdentityMigrationCarriesUncertainty(t *testing.T) {
	for _, state := range []TransitionState{TransitionReapplyPending, TransitionBlocked} {
		t.Run(string(state), func(t *testing.T) {
			s := candidateStore(t)
			ctx := context.Background()
			if err := testCommit(s, ctx); err != nil {
				t.Fatal(err)
			}
			before := runningState(t, s)
			if state == TransitionBlocked {
				if err := s.blockTransitionLocked(ctx, before.Revision, "uncertain"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec(`UPDATE configs SET data = json_set(data, '$.schema_version', '0.1.8')
 WHERE key IN (?, ?)`, configKeyRunning, configKeyPrevious); err != nil {
				t.Fatal(err)
			}
			s = reopenSnapshotStore(t, s)
			after := runningState(t, s)
			assertFreshRunning(t, before, after)
			if after.Transition == nil || after.Transition.ID != before.Transition.ID ||
				after.Transition.State != state || after.Transition.RunningRevision != after.RunningRevision ||
				after.Transition.Revision != after.Revision {
				t.Fatal("migration lost or mislabelled uncertainty")
			}
		})
	}
}

func TestRunningIdentityLegacyMigrationWaitsForGenesis(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	markLegacyIdentity(t, s)
	if _, err := s.db.Exec(`UPDATE configs SET data = json_set(data, '$.schema_version', '0.1.8')
 WHERE key = ?`, configKeyRunning); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MigrateIndustrialScope(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM running_identity`).Scan(&count); err != nil || count != 0 {
		t.Fatal("legacy migration minted an intermediate identity", count, err)
	}
	if err := s.initializeRunningIdentities(ctx); err != nil {
		t.Fatal(err)
	}
	if !runningState(t, s).RunningRevision.Valid() {
		t.Fatal("genesis omitted final identity")
	}
}
