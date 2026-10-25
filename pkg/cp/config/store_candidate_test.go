// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func candidateStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	cfg := DefaultConfig()
	cfg.System.Hostname = "running"
	cfg.IDS.Rules = DefaultIDSConfig().Rules[:1]
	if err := s.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCandidateSeedingIsReadOnly(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	running, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := s.LoadCandidate(ctx)
	if err != nil || !reflect.DeepEqual(candidate, running) {
		t.Fatalf("seed differs: %v", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM configs WHERE key = ?`, configKeyCandidate).Scan(&count); err != nil || count != 0 {
		t.Fatalf("read persisted candidate: count=%d err=%v", count, err)
	}
}

func TestCandidateConcurrentEditsPreserveEachOther(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			err := s.MutateCandidate(ctx, func(cfg *Config) error {
				cfg.Assets = append(cfg.Assets, Asset{ID: fmt.Sprint(i), Name: fmt.Sprint(i)})
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	cfg, err := s.LoadCandidate(ctx)
	if err != nil || len(cfg.Assets) != 40 {
		t.Fatalf("lost edits: %+v err=%v", cfg, err)
	}
}

func TestCandidateIDSCommitAndRollback(t *testing.T) {
	for _, mode := range []string{"plain", "confirmed", "timed", "superseded"} {
		t.Run(mode, func(t *testing.T) {
			s := candidateStore(t)
			ctx := context.Background()
			before, err := s.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.MutateCandidate(ctx, func(cfg *Config) error {
				cfg.System.Hostname = "candidate"
				cfg.IDS.Rules = DefaultIDSConfig().Rules[1:2]
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if mode == "plain" {
				err = s.Commit(ctx)
			} else {
				err = s.CommitConfirmed(ctx, 100*time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			running, err := s.Load(ctx)
			if err != nil || running.System.Hostname != "candidate" || running.IDS.Rules[0].ID == before.IDS.Rules[0].ID {
				t.Fatalf("promotion: %+v %v", running, err)
			}
			if mode == "superseded" {
				before = running
				if err := s.MutateCandidate(ctx, func(cfg *Config) error {
					cfg.System.Hostname = "superseding"
					cfg.IDS.Rules = []IDSRule{}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := s.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				time.Sleep(150 * time.Millisecond)
				running, err = s.Load(ctx)
				if err != nil || running.System.Hostname != "superseding" || len(running.IDS.Rules) != 0 {
					t.Fatalf("plain commit did not cancel timer: %+v %v", running, err)
				}
			}
			if mode == "timed" {
				deadline := time.Now().Add(3 * time.Second)
				for {
					running, err = s.Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if running.System.Hostname == before.System.Hostname {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("timed rollback did not fire")
					}
					time.Sleep(time.Millisecond)
				}
			} else if err := s.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			running, err = s.Load(ctx)
			if err != nil || !reflect.DeepEqual(running, before) {
				t.Fatalf("rollback did not restore config and bank: got=%+v want=%+v err=%v", running, before, err)
			}
			bank, err := s.LoadIDSRules(ctx)
			if err != nil || !reflect.DeepEqual(bank, before.IDS.Rules) {
				t.Fatalf("rollback bank=%+v err=%v", bank, err)
			}
		})
	}
}

func TestCandidatePromotionFailureIsAtomic(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	before, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MutateCandidate(ctx, func(cfg *Config) error {
		cfg.System.Hostname = "must-not-promote"
		cfg.IDS.Rules = DefaultIDSConfig().Rules[1:2]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_promotion BEFORE INSERT ON configs WHEN NEW.key = 'running' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx); err == nil {
		t.Fatal("injected database error should abort the transaction")
	}
	after, err := s.Load(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("partial promotion: %+v err=%v", after, err)
	}
	candidate, err := s.LoadCandidate(ctx)
	if err != nil || candidate.System.Hostname != "must-not-promote" {
		t.Fatalf("failed promotion lost candidate: %+v err=%v", candidate, err)
	}
}

func TestRollbackPreservesNewerCandidateEdits(t *testing.T) {
	for _, timed := range []bool{false, true} {
		t.Run(fmt.Sprint("timed=", timed), func(t *testing.T) {
			s := candidateStore(t)
			ctx := context.Background()
			original, err := s.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.MutateCandidate(ctx, func(cfg *Config) error {
				cfg.System.Hostname = "confirmed"
				cfg.IDS.Rules = DefaultIDSConfig().Rules[1:2]
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.CommitConfirmed(ctx, 100*time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if err := s.MutateCandidate(ctx, func(cfg *Config) error {
				cfg.Description = "newer edit"
				cfg.IDS.Rules = DefaultIDSConfig().Rules[2:3]
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			desired, err := s.LoadCandidate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if timed {
				deadline := time.Now().Add(3 * time.Second)
				for {
					running, err := s.Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if running.System.Hostname == original.System.Hostname {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("timed rollback did not fire")
					}
					time.Sleep(time.Millisecond)
				}
			} else if err := s.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			running, err := s.Load(ctx)
			if err != nil || !reflect.DeepEqual(running, original) {
				t.Fatalf("rollback failed: %+v %v", running, err)
			}
			candidate, err := s.LoadCandidate(ctx)
			if err != nil || !reflect.DeepEqual(candidate, desired) {
				t.Fatalf("rollback lost newer candidate: %+v %v", candidate, err)
			}
		})
	}
}
