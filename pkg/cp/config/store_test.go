// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAutoRollbackNotificationNeverBlocks(t *testing.T) {
	for _, capacity := range []int{0, 1} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			notify := make(chan struct{}, capacity)
			if capacity > 0 {
				notify <- struct{}{} // A full channel must not block either.
			}
			store.SetAutoRollbackNotify(notify)
			ctx := context.Background()
			if err := store.Save(ctx, &Config{System: SystemConfig{Hostname: "previous"}}); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveCandidate(ctx, &Config{System: SystemConfig{Hostname: "pending"}}); err != nil {
				t.Fatal(err)
			}
			if err := store.CommitConfirmed(ctx, 10*time.Millisecond); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				cfg, err := store.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if cfg.System.Hostname == "previous" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("rollback did not fire")
				}
				time.Sleep(time.Millisecond)
			}
			done := make(chan error, 1)
			go func() { done <- store.ConfirmCommit(ctx) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("notification blocked timer while holding store mutex")
			}
		})
	}
}

func TestPendingCommitRearmedAtStoreOpen(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint("expired=", expired), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cfg.db")
			store, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := store.Save(ctx, &Config{System: SystemConfig{Hostname: "previous"}}); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveCandidate(ctx, &Config{System: SystemConfig{Hostname: "pending"}}); err != nil {
				t.Fatal(err)
			}
			if err := store.CommitConfirmed(ctx, time.Hour); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(100 * time.Millisecond)
			if expired {
				deadline = time.Now().Add(-time.Second)
			}
			blob, err := json.Marshal(pendingCommit{DeadlineUnix: deadline.UnixNano()})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(`UPDATE configs SET data = ? WHERE key = ?`, string(blob), configKeyPending); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			notify := make(chan struct{}, 1)
			store.SetAutoRollbackNotify(notify)
			if !expired {
				select {
				case <-notify:
				case <-time.After(3 * time.Second):
					t.Fatal("reopened store did not re-arm pending rollback")
				}
			}
			cfg, err := store.Load(ctx)
			if err != nil || cfg.System.Hostname != "previous" {
				t.Fatalf("reopened rollback config=%+v err=%v", cfg, err)
			}
			if _, err := store.loadPending(ctx); !errors.Is(err, ErrNotFound) {
				t.Fatalf("pending state not cleared: %v", err)
			}
			select {
			case <-notify:
				t.Fatal("unexpected extra rollback notification")
			default:
			}
		})
	}
}

func TestSQLiteStoreSaveLoad(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cfg.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	cfg := Config{
		System: SystemConfig{Hostname: "containd"},
		Zones:  []Zone{{Name: "it"}},
		Interfaces: []Interface{
			{Name: "eth0", Zone: "it", Addresses: []string{"192.168.1.1/24"}},
		},
		Firewall: FirewallConfig{
			DefaultAction: ActionDeny,
			Rules: []Rule{
				{ID: "1", SourceZones: []string{"it"}, DestZones: []string{"it"}, Action: ActionAllow},
			},
		},
	}
	if err := store.Save(context.Background(), &cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.System.Hostname != cfg.System.Hostname {
		t.Fatalf("hostname mismatch: got %s want %s", loaded.System.Hostname, cfg.System.Hostname)
	}
	if len(loaded.Zones) != 1 || loaded.Zones[0].Name != "it" {
		t.Fatalf("zones mismatch: %+v", loaded.Zones)
	}
	if len(loaded.Firewall.Rules) != 1 || loaded.Firewall.Rules[0].ID != "1" {
		t.Fatalf("rules mismatch: %+v", loaded.Firewall.Rules)
	}
}

func TestSQLiteStoreNotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.Load(context.Background())
	if err == nil || err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStoreRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// missing zone referenced by interface
	cfg := Config{
		Interfaces: []Interface{{Name: "eth0", Zone: "missing"}},
	}
	if err := store.Save(context.Background(), &cfg); err == nil {
		t.Fatalf("expected validation error on save")
	}
}

func TestCandidateCommitRollback(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	running := Config{System: SystemConfig{Hostname: "running"}}
	if err := store.Save(context.Background(), &running); err != nil {
		t.Fatalf("save running: %v", err)
	}
	candidate := Config{System: SystemConfig{Hostname: "candidate"}}
	if err := store.SaveCandidate(context.Background(), &candidate); err != nil {
		t.Fatalf("save candidate: %v", err)
	}
	if err := store.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	got, _ := store.Load(context.Background())
	if got.System.Hostname != "candidate" {
		t.Fatalf("expected committed candidate, got %s", got.System.Hostname)
	}
	if err := store.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, _ = store.Load(context.Background())
	if got.System.Hostname != "running" {
		t.Fatalf("expected rollback to running, got %s", got.System.Hostname)
	}
}

func TestCommitWithoutCandidateDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	running := Config{System: SystemConfig{Hostname: "running"}}
	if err := store.Save(context.Background(), &running); err != nil {
		t.Fatalf("save running: %v", err)
	}
	if err := store.Commit(context.Background()); err != nil {
		t.Fatalf("initial commit: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- store.Commit(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second commit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second commit deadlocked with no candidate")
	}

	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load running: %v", err)
	}
	if got.System.Hostname != running.System.Hostname {
		t.Fatalf("running config changed: got %q want %q", got.System.Hostname, running.System.Hostname)
	}
}

func TestCommitConfirmedWithoutCandidateDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	running := Config{System: SystemConfig{Hostname: "running"}}
	if err := store.Save(context.Background(), &running); err != nil {
		t.Fatalf("save running: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- store.CommitConfirmed(context.Background(), time.Minute) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("commit confirmed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("commit confirmed deadlocked with no candidate")
	}
}

func TestCommitConfirmedAutoRollback(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	running := Config{System: SystemConfig{Hostname: "running"}}
	if err := store.Save(context.Background(), &running); err != nil {
		t.Fatalf("save running: %v", err)
	}
	candidate := Config{System: SystemConfig{Hostname: "candidate"}}
	if err := store.SaveCandidate(context.Background(), &candidate); err != nil {
		t.Fatalf("save candidate: %v", err)
	}
	if err := store.CommitConfirmed(context.Background(), 100*time.Millisecond); err != nil {
		t.Fatalf("commit confirmed: %v", err)
	}
	got, _ := store.Load(context.Background())
	if got.System.Hostname != "candidate" {
		t.Fatalf("expected committed candidate, got %s", got.System.Hostname)
	}
	time.Sleep(200 * time.Millisecond)
	got, _ = store.Load(context.Background())
	if got.System.Hostname != "running" {
		t.Fatalf("expected auto-rollback to running, got %s", got.System.Hostname)
	}
}

func TestConfirmCommitCancelsRollback(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	running := Config{System: SystemConfig{Hostname: "running"}}
	if err := store.Save(context.Background(), &running); err != nil {
		t.Fatalf("save running: %v", err)
	}
	candidate := Config{System: SystemConfig{Hostname: "candidate"}}
	if err := store.SaveCandidate(context.Background(), &candidate); err != nil {
		t.Fatalf("save candidate: %v", err)
	}
	if err := store.CommitConfirmed(context.Background(), 100*time.Millisecond); err != nil {
		t.Fatalf("commit confirmed: %v", err)
	}
	if err := store.ConfirmCommit(context.Background()); err != nil {
		t.Fatalf("confirm commit: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	got, _ := store.Load(context.Background())
	if got.System.Hostname != "candidate" {
		t.Fatalf("expected confirmed candidate to remain, got %s", got.System.Hostname)
	}
}

func TestRejectsNewerSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	cfg := Config{
		SchemaVersion: "9.9.9",
		System:        SystemConfig{Hostname: "containd"},
	}
	if err := store.Save(context.Background(), &cfg); err == nil {
		t.Fatalf("expected error for newer schema version")
	}
}

// Ensure database file is created on init.
func TestSQLiteStoreCreatesFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cfg.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	store.Close()
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected db file to exist: %v", err)
	}
}

func TestSQLiteStoreWipeAllClearsIDSRules(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	cfg := DefaultConfig()
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatalf("save default config: %v", err)
	}
	if rules, err := store.LoadIDSRules(context.Background()); err != nil || len(rules) == 0 {
		t.Fatalf("expected seeded ids rules before wipe, got %d %v", len(rules), err)
	}

	if err := store.WipeAll(context.Background()); err != nil {
		t.Fatalf("wipe all: %v", err)
	}

	if _, err := store.Load(context.Background()); err != ErrNotFound {
		t.Fatalf("expected config not found after wipe, got %v", err)
	}
	rules, err := store.LoadIDSRules(context.Background())
	if err != nil {
		t.Fatalf("load ids rules after wipe: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected ids rules cleared after wipe, got %d", len(rules))
	}
}
