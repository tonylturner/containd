// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestSavePreservesStagedStateAndUnchangedBank(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	if err := s.CommitConfirmed(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.MutateCandidate(ctx, func(cfg *Config) error {
		cfg.Description = "staged"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := storeRows(t, s)
	if _, err := s.db.Exec(`CREATE TRIGGER no_bank_rewrite BEFORE DELETE ON ids_rules BEGIN SELECT RAISE(ABORT, 'unchanged bank rewritten'); END`); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.System.Hostname = "saved"
	if err := s.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	after := storeRows(t, s)
	for _, key := range []string{configKeyCandidate, configKeyPrevious, configKeyPending} {
		if before[key] != after[key] {
			t.Fatalf("Save changed %s", key)
		}
	}
}

func TestSaveIDSBankIntent(t *testing.T) {
	for _, mode := range []string{"omitted", "empty", "changed", "reordered"} {
		t.Run(mode, func(t *testing.T) {
			s := candidateStore(t)
			ctx := context.Background()
			cfg, err := s.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			want := cfg.IDS.Rules
			switch mode {
			case "omitted":
				cfg.IDS.Rules = nil
			case "empty":
				cfg.IDS.Rules = []IDSRule{}
				want = nil
			case "changed":
				cfg.IDS.Rules = DefaultIDSConfig().Rules[1:2]
				want = cfg.IDS.Rules
			case "reordered":
				cfg.IDS.Rules = DefaultIDSConfig().Rules[:2]
				if err := s.Save(ctx, cfg); err != nil {
					t.Fatal(err)
				}
				want, err = s.LoadIDSRules(ctx)
				if err != nil {
					t.Fatal(err)
				}
				cfg.IDS.Rules[0], cfg.IDS.Rules[1] = cfg.IDS.Rules[1], cfg.IDS.Rules[0]
				if _, err := s.db.Exec(`CREATE TRIGGER no_bank_rewrite BEFORE DELETE ON ids_rules BEGIN SELECT RAISE(ABORT, 'reordered bank rewritten'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Save(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			got, err := s.LoadIDSRules(ctx)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("Save bank intent lost: got=%v want=%v err=%v", got, want, err)
			}
		})
	}
}

func storeRows(t *testing.T, s *SQLiteStore) map[string]string {
	t.Helper()
	rows, err := s.db.Query(`SELECT key, data FROM configs`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key, data string
		if err := rows.Scan(&key, &data); err != nil {
			t.Fatal(err)
		}
		out[key] = data
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRepairTransaction(t *testing.T) {
	for _, mode := range []string{"success", "no-candidate", "edit-error", "validation-error", "write-error"} {
		t.Run(mode, func(t *testing.T) {
			s := candidateStore(t)
			ctx := context.Background()
			if err := s.CommitConfirmed(ctx, time.Hour); err != nil {
				t.Fatal(err)
			}
			if mode != "no-candidate" {
				if err := s.MutateCandidate(ctx, func(cfg *Config) error {
					cfg.Description = "staged"
					cfg.IDS.Rules = DefaultIDSConfig().Rules[1:2]
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			before := storeRows(t, s)
			rulesBefore, err := s.LoadIDSRules(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "write-error" {
				if _, err := s.db.Exec(`CREATE TRIGGER fail_repair BEFORE INSERT ON configs WHEN NEW.key = 'candidate' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			_, err = Repair(ctx, s, func(cfg *Config) error {
				cfg.System.Hostname = "repaired"
				if cfg.Description == "staged" {
					switch mode {
					case "edit-error":
						return errors.New("cannot repair candidate")
					case "validation-error":
						cfg.IDS.Rules[0].ID = ""
					}
				}
				return nil
			})
			after := storeRows(t, s)
			if mode == "success" || mode == "no-candidate" {
				if err != nil {
					t.Fatal(err)
				}
				if before[configKeyPrevious] != after[configKeyPrevious] || before[configKeyPending] != after[configKeyPending] {
					t.Fatal("repair changed rollback state")
				}
				if mode == "no-candidate" {
					if _, exists := after[configKeyCandidate]; exists {
						t.Fatal("repair seeded a candidate")
					}
				} else {
					candidate, err := s.LoadCandidate(ctx)
					if err != nil || candidate.Description != "staged" || candidate.System.Hostname != "repaired" || candidate.IDS.Rules[0].ID == rulesBefore[0].ID {
						t.Fatalf("repair lost staged edit/bank: %+v %v", candidate, err)
					}
					if err := s.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				}
				running, err := s.Load(ctx)
				if err != nil || running.System.Hostname != "repaired" {
					t.Fatalf("repair reverted on commit: %+v %v", running, err)
				}
			} else {
				if err == nil || !reflect.DeepEqual(before, after) {
					t.Fatalf("failed repair not atomic: err=%v", err)
				}
				rulesAfter, err := s.LoadIDSRules(ctx)
				if err != nil || !reflect.DeepEqual(rulesBefore, rulesAfter) {
					t.Fatalf("failed repair changed bank: %v", err)
				}
			}
		})
	}
}

func BenchmarkStageWith30KRuleBank(b *testing.B) {
	s, err := NewSQLiteStore(b.TempDir() + "/config.db")
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	cfg := DefaultConfig()
	cfg.IDS.Rules = make([]IDSRule, 30000)
	template := DefaultIDSConfig().Rules[0]
	for i := range cfg.IDS.Rules {
		cfg.IDS.Rules[i] = template
		cfg.IDS.Rules[i].ID = fmt.Sprintf("rule-%05d", i)
	}
	ctx := context.Background()
	if err := s.Save(ctx, cfg); err != nil {
		b.Fatal(err)
	}
	if err := s.SaveCandidate(ctx, cfg); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.MutateCandidate(ctx, func(next *Config) error {
			next.Description = fmt.Sprintf("edit-%d", i)
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	var size int
	if err := s.db.QueryRow(`SELECT length(data) FROM configs WHERE key = ?`, configKeyCandidate).Scan(&size); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(size), "snapshot-bytes")
}
