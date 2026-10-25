// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestLegacySnapshotsKeepDeployedBank(t *testing.T) {
	for _, mode := range []string{"rollback", "expired", "candidate"} {
		t.Run(mode, func(t *testing.T) {
			s := candidateStore(t)
			ctx := context.Background()
			before, err := s.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			legacy := cloneConfigForPersist(before)
			legacy.System.Hostname = "legacy"
			legacy.IDS.Rules = nil
			raw, err := json.Marshal(legacy) // Exact pre-marker storage format.
			if err != nil {
				t.Fatal(err)
			}
			key := configKeyPrevious
			if mode == "candidate" {
				key = configKeyCandidate
			}
			if _, err := s.db.Exec(`REPLACE INTO configs VALUES (?, ?, 123)`, key, string(raw)); err != nil {
				t.Fatal(err)
			}
			if mode == "expired" {
				pending, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(-time.Hour).UnixNano()})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(`INSERT INTO configs VALUES (?, ?, 123)`, configKeyPending, string(pending)); err != nil {
					t.Fatal(err)
				}
			}
			var path string
			if err := s.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name = 'main'`).Scan(&path); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if mode != "expired" {
				// Legacy "unchanged" means the bank at use time, not at migration.
				before.IDS.Rules = DefaultIDSConfig().Rules[1:2]
				if err := s.SaveIDSRules(ctx, before.IDS.Rules); err != nil {
					t.Fatal(err)
				}
				if mode == "candidate" {
					err = s.Commit(ctx)
				} else {
					err = s.Rollback(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.Load(ctx)
			if err != nil || got.System.Hostname != "legacy" || !reflect.DeepEqual(got.IDS.Rules, before.IDS.Rules) {
				t.Fatalf("lost bank or config: got=%+v err=%v", got, err)
			}
		})
	}
}

func TestSnapshotEmptyBankSurvivesReopen(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	if err := s.MutateCandidate(ctx, func(cfg *Config) error {
		cfg.IDS.Rules = []IDSRule{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s = reopenSnapshotStore(t, s)
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Snapshot the empty bank as previous, then put rules back in running.
	if err := s.MutateCandidate(ctx, func(cfg *Config) error {
		cfg.IDS.Rules = DefaultIDSConfig().Rules[:1]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	s = reopenSnapshotStore(t, s)
	if err := s.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	rules, err := s.LoadIDSRules(ctx)
	if err != nil || len(rules) != 0 {
		t.Fatalf("explicitly empty previous bank was lost: %v %v", rules, err)
	}
}

func reopenSnapshotStore(t *testing.T, s *SQLiteStore) *SQLiteStore {
	t.Helper()
	var path string
	if err := s.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name = 'main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { next.Close() })
	return next
}

func TestUnversionedEmbeddedBankIsPreserved(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	previous, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	previous.IDS.Rules = DefaultIDSConfig().Rules[1:2]
	raw, err := json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO configs VALUES (?, ?, 123)`, configKeyPrevious, string(raw)); err != nil {
		t.Fatal(err)
	}
	s = reopenSnapshotStore(t, s)
	if err := s.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	rules, err := s.LoadIDSRules(ctx)
	if err != nil || !reflect.DeepEqual(rules, previous.IDS.Rules) {
		t.Fatalf("lost pre-marker embedded bank: %v %v", rules, err)
	}
}

func TestSnapshotRejectsUnknownFormat(t *testing.T) {
	s := candidateStore(t)
	// Derive a guaranteed unsupported version from the loaded authority.
	raw := fmt.Sprintf(`{"snapshot_format":%d}`, snapshotFormatEmbeddedBank+1)
	if _, err := s.db.Exec(`INSERT INTO configs VALUES (?, ?, 123)`, configKeyCandidate, raw); err != nil {
		t.Fatal(err)
	}
	if err := s.upgradeSnapshots(context.Background()); err == nil {
		t.Fatal("accepted unknown snapshot format")
	}
}
