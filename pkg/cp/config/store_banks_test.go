// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestBankFreeMutationRejectsRulesAndNeverReadsBank(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	before := storeRows(t, s)
	for _, rules := range [][]IDSRule{{}, DefaultIDSConfig().Rules[:1]} {
		if err := testMutateCandidate(s, ctx, func(c *Config) error {
			if c.IDS.Rules != nil {
				t.Fatal("callback received bank")
			}
			c.IDS.Rules = rules
			return nil
		}); err == nil {
			t.Fatal("accepted bank-free edit supplying rules")
		}
		if !reflect.DeepEqual(before, storeRows(t, s)) {
			t.Fatal("rejected edit changed storage")
		}
	}
	id, err := bankReference(ctx, s.db, configKeyRunning)
	if err != nil {
		t.Fatal(err)
	}
	// An unreadable bank proves the ordinary edit neither loads nor validates it.
	// Deny every bank write as well, including the engine consumer table.
	for _, query := range []string{
		`UPDATE ids_banks SET data = 'invalid JSON'`,
		`CREATE TRIGGER no_bank_insert BEFORE INSERT ON ids_banks BEGIN SELECT RAISE(ABORT, 'bank rewritten'); END`,
		`CREATE TRIGGER no_bank_update BEFORE UPDATE ON ids_banks BEGIN SELECT RAISE(ABORT, 'bank rewritten'); END`,
		`CREATE TRIGGER no_rules_delete BEFORE DELETE ON ids_rules BEGIN SELECT RAISE(ABORT, 'rules rewritten'); END`,
	} {
		if _, err := s.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 { // Both running seeding and an existing candidate.
		doc, err := s.LoadCandidateDocument(ctx)
		if err != nil || doc.IDS.Rules != nil {
			t.Fatalf("document read touched bank: %v", err)
		}
		if err := testMutateCandidate(s, ctx, func(c *Config) error { c.Description = "cheap edit"; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	got, err := bankReference(ctx, s.db, configKeyCandidate)
	if err != nil || got != id {
		t.Fatalf("bank reference changed: %d != %d: %v", got, id, err)
	}
}

func TestPairedReadWithConcurrentPromotions(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 1; i <= 100; i++ {
			if err := testMutateCandidate(s, ctx, func(c *Config) error { c.Description = strconv.Itoa(i); return nil }); err != nil {
				t.Error(err)
				return
			}
			if err := testCommit(s, ctx); err != nil {
				t.Error(err)
				return
			}
		}
	})
	for range 150 {
		running, candidate, err := s.LoadPair(ctx)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := strconv.Atoi(running.Description)
		c, _ := strconv.Atoi(candidate.Description)
		if r > c || c > r+1 {
			t.Fatalf("torn pair: %d -> %d", r, c)
		}
		candidate.IDS.Rules[0].ID = "detached"
		if running.IDS.Rules[0].ID == "detached" {
			t.Fatal("pair aliases bank memory")
		}
	}
	wg.Wait()
}

// Build the previous schema directly, without using today's store constructor.
func oldBankDatabase(t *testing.T, failMigration bool) (string, map[string]*Config) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, query := range []string{
		`CREATE TABLE configs (key TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL)`,
		`CREATE TABLE ids_rules (id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL)`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	states := map[string]*Config{}
	for i, key := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
		cfg := DefaultConfig()
		cfg.Description = key
		cfg.IDS.Rules = DefaultIDSConfig().Rules[i : i+1]
		if key == configKeyCandidate {
			cfg.IDS.Rules = []IDSRule{}
		}
		wire, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var expected Config
		if err := json.Unmarshal(wire, &expected); err != nil {
			t.Fatal(err)
		}
		if err := UpgradeInPlace(&expected); err != nil {
			t.Fatal(err)
		}
		if key == configKeyCandidate {
			expected.IDS.Rules = []IDSRule{}
		}
		states[key] = &expected
		stored := storedConfig{Config: *cfg, SnapshotFormat: snapshotFormatEmbeddedBank}
		if key == configKeyRunning {
			stored.IDS.Rules = nil
			stored.SnapshotFormat = 0
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if err := replaceIDSRulesTx(context.Background(), tx, cfg.IDS.Rules); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		blob, err := json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO configs VALUES (?, ?, 123)`, key, string(blob)); err != nil {
			t.Fatal(err)
		}
	}
	if failMigration {
		if _, err := db.Exec(`CREATE TRIGGER reject_extract BEFORE UPDATE ON configs WHEN NEW.key = 'previous' BEGIN SELECT RAISE(ABORT, 'extraction failed'); END`); err != nil {
			t.Fatal(err)
		}
	}
	return path, states
}

func TestExtractEmbeddedBanksFromPreviousSchema(t *testing.T) {
	path, states := oldBankDatabase(t, false)
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ids := map[string]int64{}
	for key, want := range states {
		got, err := s.loadKind(ctx, key)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s migration lost config/bank: %v", key, err)
		}
		id, err := bankReference(ctx, s.db, key)
		if err != nil || id == 0 {
			t.Fatalf("%s bank reference: %d %v", key, id, err)
		}
		ids[key] = id
		doc, err := readKindFrom(ctx, s.db, key, false)
		if err != nil || doc.IDS.Rules != nil {
			t.Fatalf("%s embedded bank remains: %v", key, err)
		}
	}
	s = reopenSnapshotStore(t, s)
	for key, id := range ids {
		got, err := bankReference(ctx, s.db, key)
		if err != nil || got != id {
			t.Fatalf("migration not idempotent: %s %d != %d: %v", key, got, id, err)
		}
	}
	if err := testCommitConfirmed(s, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx)
	if err != nil || len(got.IDS.Rules) != 0 {
		t.Fatalf("migrated empty candidate not promoted: %v", err)
	}
	if err := testRollback(s, ctx); err != nil {
		t.Fatal(err)
	}
	got, err = s.Load(ctx)
	if err != nil || !reflect.DeepEqual(got, states[configKeyRunning]) {
		t.Fatalf("migrated running bank not restored: %v", err)
	}
}

func TestBankExtractionIsTransactional(t *testing.T) {
	path, _ := oldBankDatabase(t, true)
	s, err := NewSQLiteStore(path)
	if err == nil {
		s.Close()
		t.Fatal("migration should fail")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM ids_banks`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial bank extraction: %d %v", count, err)
	}
	for _, key := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
		id, err := bankReference(context.Background(), db, key)
		if err != nil || id != 0 {
			t.Fatalf("partial reference extraction: %s %d %v", key, id, err)
		}
	}
}

func TestBankReferencesSurviveApplyRecovery(t *testing.T) {
	for _, change := range []RunningChange{ChangeCommit, ChangeCommitConfirmed, ChangeRollback} {
		t.Run(string(change), func(t *testing.T) {
			s := resetTestStore(t)
			before := resetConfigRows(t, s)
			running, candidate, err := s.LoadPair(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			err = testApplyChange(s, ctx, change, time.Hour, func(ctx context.Context, _, next *Config) error {
				calls++
				if calls == 1 {
					cancel()
					return fmt.Errorf("runtime failed")
				}
				if ctx.Err() != nil || !reflect.DeepEqual(next, running) {
					t.Fatal("reapply lost config/bank or recovery context")
				}
				return nil
			})
			var failure *ApplyError
			if !errors.As(err, &failure) || failure.RestoreError != nil || failure.ReapplyError != nil || calls != 2 {
				t.Fatalf("recovery failed: %v", err)
			}
			if !reflect.DeepEqual(before, resetConfigRows(t, s)) {
				t.Fatal("recovery changed pinned references")
			}
			gotRunning, gotCandidate, err := s.LoadPair(context.Background())
			if err != nil || !reflect.DeepEqual(gotRunning, running) || !reflect.DeepEqual(gotCandidate, candidate) {
				t.Fatalf("recovery lost bank: %v", err)
			}
		})
	}
}

func TestSaveRetainsBankWrittenBeforeFirstConfig(t *testing.T) {
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "rules-first.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	rules := DefaultIDSConfig().Rules[:1]
	if err := s.SaveIDSRules(ctx, rules); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.IDS.Rules = nil
	if err := s.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx)
	if err != nil || len(got.IDS.Rules) != 1 || got.IDS.Rules[0].ID != rules[0].ID {
		t.Fatalf("standalone bank lost: %v", err)
	}
}
