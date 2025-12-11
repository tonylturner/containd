package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
