// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Decode references independently of the collector's SQL, including fault rows
// that are not JSON, and check both dangling references and orphan generations.
func assertBankCollection(t *testing.T, s *SQLiteStore, limit int) map[int64]bool {
	t.Helper()
	refs := map[int64]bool{}
	rows, err := s.db.Query(`SELECT data FROM configs`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var metadata struct {
			BankID int64 `json:"ids_bank"`
		}
		if json.Unmarshal([]byte(raw), &metadata) == nil && metadata.BankID != 0 {
			refs[metadata.BankID] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	rows, err = s.db.Query(`SELECT id FROM ids_banks`)
	if err != nil {
		t.Fatal(err)
	}
	banks := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		banks[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(refs, banks) || len(banks) > limit {
		t.Fatalf("bank collection: refs=%v banks=%v limit=%d", refs, banks, limit)
	}
	if s.recoveryHoldsBanks {
		t.Fatal("recovery hold leaked after operation")
	}
	return banks
}

func replaceGCTestBank(t *testing.T, s *SQLiteStore, label string) {
	t.Helper()
	if err := testMutateCandidateIDS(s, context.Background(), func(cfg *Config) error {
		cfg.IDS.Rules = append([]IDSRule(nil), DefaultIDSConfig().Rules[:1]...)
		cfg.IDS.Rules[0].ID = label
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBankGCReplacementPathsAreBounded(t *testing.T) {
	for _, mode := range []string{"save", "save_rules", "candidate", "mutate", "repair", "commit", "confirmed", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			s := resetTestStore(t)
			ctx := context.Background()
			for i := range 12 {
				cfg, err := s.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				cfg.IDS.Rules = append([]IDSRule(nil), DefaultIDSConfig().Rules[:1]...)
				cfg.IDS.Rules[0].ID = fmt.Sprintf("replacement-%d", i)
				switch mode {
				case "save":
					err = s.Save(ctx, cfg)
				case "save_rules":
					err = s.SaveIDSRules(ctx, cfg.IDS.Rules)
				case "candidate":
					err = testSaveCandidate(s, ctx, cfg)
				case "mutate":
					replaceGCTestBank(t, s, cfg.IDS.Rules[0].ID)
				case "repair":
					_, err = Repair(ctx, s, func(c *Config) error { c.IDS.Rules = cfg.IDS.Rules; return nil })
				default:
					err = testSaveCandidate(s, ctx, cfg)
					if err == nil {
						if mode == "confirmed" {
							err = testCommitConfirmed(s, ctx, time.Hour)
						} else {
							err = testCommit(s, ctx)
						}
					}
					if err == nil && mode == "rollback" {
						err = testRollback(s, ctx)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				assertBankCollection(t, s, 3)
			}
		})
	}
}

func TestBankGCPinsRecoveryAcrossImports(t *testing.T) {
	for _, mode := range []string{"commit", "commit_confirmed", "rollback", "reset"} {
		t.Run(mode, func(t *testing.T) {
			s := resetTestStore(t)
			ctx := context.Background()
			previous, err := loadKindFrom(ctx, s.db, configKeyPrevious)
			if err != nil {
				t.Fatal(err)
			}
			for i := range 12 {
				replaceGCTestBank(t, s, fmt.Sprintf("before-failure-%d", i))
			}
			before := resetConfigRows(t, s)
			banks := assertBankCollection(t, s, 3)
			running, err := s.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			caller, cancel := context.WithCancel(ctx)
			defer cancel()
			calls := 0
			apply := func(ctx context.Context, _, next *Config) error {
				calls++
				// White-box reads only: callbacks must never reenter Store. In each
				// transition at least one saved bank has lost its live reference.
				for id := range banks {
					var count int
					if err := s.db.QueryRow(`SELECT count(*) FROM ids_banks WHERE id = ?`, id).Scan(&count); err != nil || count != 1 {
						t.Fatalf("deleted recovery bank %d: %d %v", id, count, err)
					}
				}
				if !s.recoveryHoldsBanks {
					t.Fatal("apply did not pin saved banks")
				}
				if calls == 1 {
					cancel()
					return errors.New("runtime apply failed")
				}
				if ctx.Err() != nil || !reflect.DeepEqual(next, running) {
					t.Fatal("recovery lost its bank or independent context")
				}
				return nil
			}
			if mode == "reset" {
				err = testApplyReset(s, caller, DefaultConfig(), apply)
			} else {
				err = testApplyChange(s, caller, RunningChange(mode), time.Hour, apply)
			}
			var failure *ApplyError
			if !errors.As(err, &failure) || failure.RestoreError != nil || failure.ReapplyError != nil || failure.HealthError != nil || calls != 2 {
				t.Fatalf("recovery: %v calls=%d", err, calls)
			}
			if !reflect.DeepEqual(before, resetConfigRows(t, s)) {
				t.Fatal("saved rows or confirmed-commit deadline changed")
			}
			assertBankCollection(t, s, 3)
			// Imports before and after recovery must not collect the pending
			// confirmed commit's previous bank; it remains the rollback authority.
			for i := range 12 {
				replaceGCTestBank(t, s, fmt.Sprintf("after-failure-%d", i))
				assertBankCollection(t, s, 3)
			}
			if err := testRollback(s, ctx); err != nil {
				t.Fatal(err)
			}
			got, err := s.Load(ctx)
			if err != nil || !reflect.DeepEqual(got, previous) {
				t.Fatalf("rollback after imports lost its bank: %v", err)
			}
			assertBankCollection(t, s, 3)
		})
	}
}

func TestBankGCSuccessfulApplyAndWipeLeaveNoOrphans(t *testing.T) {
	for _, mode := range []string{"commit", "commit_confirmed", "rollback", "reset"} {
		t.Run(mode, func(t *testing.T) {
			s := resetTestStore(t)
			ctx := context.Background()
			apply := func(context.Context, *Config, *Config) error { return nil }
			var err error
			if mode == "reset" {
				err = testApplyReset(s, ctx, DefaultConfig(), apply)
			} else {
				err = testApplyChange(s, ctx, RunningChange(mode), time.Hour, apply)
			}
			if err != nil {
				t.Fatal(err)
			}
			limit := 3
			if mode == "reset" {
				limit = 1
			}
			assertBankCollection(t, s, limit)
			if err := s.WipeAll(ctx); err != nil {
				t.Fatal(err)
			}
			assertBankCollection(t, s, 0)
		})
	}
}

func TestBankGCBootSweepsOrphansAndPreservesPendingRollback(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint("expired=", expired), func(t *testing.T) {
			s := resetTestStore(t)
			ctx := context.Background()
			previous, err := loadKindFrom(ctx, s.db, configKeyPrevious)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SetRuntimeApplyFault(ctx, "plain text: not JSON"); err != nil {
				t.Fatal(err)
			}
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback() //nolint:errcheck
			orphan, err := createBankTx(ctx, tx, DefaultIDSConfig().Rules)
			if err != nil {
				t.Fatal(err)
			}
			if expired {
				pending, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(-time.Hour).UnixNano()})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.ExecContext(ctx, `UPDATE configs SET data = ? WHERE key = ?`, string(pending), configKeyPending); err != nil {
					t.Fatal(err)
				}
			}
			// Simulate an orphan left by an older store or interrupted reclamation.
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			s = reopenSnapshotStore(t, s)
			assertBankCollection(t, s, 3)
			var count int
			if err := s.db.QueryRow(`SELECT count(*) FROM ids_banks WHERE id = ?`, orphan).Scan(&count); err != nil || count != 0 {
				t.Fatalf("boot retained orphan: %d %v", count, err)
			}
			if !expired {
				if err := testRollback(s, ctx); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.Load(ctx)
			if err != nil || !reflect.DeepEqual(got, previous) {
				t.Fatalf("boot sweep broke pending rollback: %v", err)
			}
			assertBankCollection(t, s, 3)
		})
	}
}

func TestBankGCFailureRollsBackReplacement(t *testing.T) {
	s := resetTestStore(t)
	before := resetConfigRows(t, s)
	if _, err := s.db.Exec(`CREATE TRIGGER deny_gc BEFORE DELETE ON ids_banks BEGIN SELECT RAISE(ABORT, 'GC denied'); END`); err != nil {
		t.Fatal(err)
	}
	err := testMutateCandidateIDS(s, context.Background(), func(c *Config) error { c.IDS.Rules = DefaultIDSConfig().Rules[:1]; return nil })
	if err == nil || !strings.Contains(err.Error(), "GC denied") {
		t.Fatalf("collection error ignored: %v", err)
	}
	if !reflect.DeepEqual(before, resetConfigRows(t, s)) {
		t.Fatal("failed GC partially committed replacement")
	}
	assertBankCollection(t, s, 3)
}

func TestBankGCSweepFailureCompensatesApply(t *testing.T) {
	s := resetTestStore(t)
	ctx := context.Background()
	before := resetConfigRows(t, s)
	running, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER deny_gc BEFORE DELETE ON ids_banks BEGIN SELECT RAISE(ABORT, 'GC denied'); END`); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = testApplyReset(s, ctx, DefaultConfig(), func(_ context.Context, _, next *Config) error {
		calls++
		if calls == 2 && !reflect.DeepEqual(next, running) {
			t.Fatal("GC failure lost recovery target")
		}
		return nil
	})
	var failure *ApplyError
	if !errors.As(err, &failure) || failure.RestoreError != nil || failure.ReapplyError != nil || failure.HealthError == nil || calls != 2 {
		t.Fatalf("GC failure did not compensate/report cleanup failure: %v calls=%d", err, calls)
	}
	if !reflect.DeepEqual(before, resetConfigRows(t, s)) || s.recoveryHoldsBanks {
		t.Fatal("GC failure changed saved state or leaked recovery hold")
	}
	if _, err := s.db.Exec(`DROP TRIGGER deny_gc`); err != nil {
		t.Fatal(err)
	}
	if err := testMutateCandidate(s, ctx, func(c *Config) error { c.Description = "retry collection"; return nil }); err != nil {
		t.Fatal(err)
	}
	assertBankCollection(t, s, 3)
}
