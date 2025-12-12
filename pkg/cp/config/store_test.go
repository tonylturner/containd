package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
			DefaultAction: ActionAllow,
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
