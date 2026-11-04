// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func TestStartupPreservesCandidateAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.db")
	t.Setenv("CONTAIND_CONFIG_DB", path)
	t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(dir, "audit.db"))
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(dir, "users.db"))
	ctx := context.Background()
	initial := &config.Config{
		System:     config.SystemConfig{Hostname: "running"},
		Zones:      []config.Zone{{Name: "wan"}},
		Interfaces: []config.Interface{{Name: "wan", Zone: "wan"}},
		IDS:        config.IDSConfig{Rules: config.DefaultIDSConfig().Rules[:1]},
	}
	wantName := "wan"
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, initial); err != nil {
		t.Fatal(err)
	}
	if err := testMutateCandidateIDS(store, ctx, func(next *config.Config) error {
		next.System.Hostname = "staged-host"
		next.System.Mgmt.HTTPSListenAddr = ":9444"
		next.Firewall.Rules = []config.Rule{{ID: "staged-rule", Action: config.ActionAllow}}
		next.IDS.Rules = config.DefaultIDSConfig().Rules[1:2]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	stores, running, err := initMgmtStores(zap.NewNop().Sugar(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stores.store.Close()
	defer stores.auditStore.Close()
	defer stores.userStore.Close()
	candidateSnapshot1, err := stores.store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
	candidate := candidateSnapshot1.Candidate
	if err != nil {
		t.Fatal(err)
	}
	if candidate.System.Hostname != "staged-host" || len(candidate.Firewall.Rules) != 1 || candidate.Firewall.Rules[0].ID != "staged-rule" {
		t.Fatalf("restart lost staged work: %+v", candidate)
	}
	for _, cfg := range []*config.Config{running, candidate} {
		if cfg.Interfaces[0].Name != wantName || cfg.System.Mgmt.HTTPListenAddr != ":8080" {
			t.Fatalf("repair missing: %+v", cfg)
		}
	}
	if running.System.Hostname != "running" || candidate.System.Mgmt.HTTPSListenAddr != ":9444" {
		t.Fatal("repair replaced unrelated settings")
	}
	if len(candidate.IDS.Rules) != 1 || candidate.IDS.Rules[0].ID == running.IDS.Rules[0].ID {
		t.Fatal("repair replaced staged bank")
	}
	if err := testCommit(stores.store, ctx); err != nil {
		t.Fatal(err)
	}
	promoted, err := stores.store.Load(ctx)
	if err != nil || promoted.Interfaces[0].Name != wantName || promoted.System.Mgmt.HTTPListenAddr != ":8080" || promoted.System.Hostname != "staged-host" {
		t.Fatalf("commit reverted startup repair: %+v %v", promoted, err)
	}
}

func TestStartupPreservesRowsAndRunningRevision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.db")
	t.Setenv("CONTAIND_CONFIG_DB", path)
	t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(dir, "audit.db"))
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(dir, "users.db"))
	device := "wan"

	ctx := context.Background()
	initial := config.DefaultConfig()
	initial.Interfaces = []config.Interface{{Name: device, Zone: "wan"}}
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, initial); err != nil {
		t.Fatal(err)
	}
	if err := ensureDefaultConfig(zap.NewNop().Sugar(), store); err != nil {
		t.Fatal(err)
	}
	before, err := store.ReadSnapshot(ctx, config.SnapshotRunning, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	stores, running, err := initMgmtStores(zap.NewNop().Sugar(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stores.store.Close()
	defer stores.auditStore.Close()
	defer stores.userStore.Close()

	after, err := stores.store.ReadSnapshot(ctx, config.SnapshotRunning, true)
	if err != nil {
		t.Fatal(err)
	}
	if after.RunningRevision != before.RunningRevision {
		t.Fatalf("boot repair changed running revision: %q -> %q; row=%q before=%+v after=%+v", before.RunningRevision, after.RunningRevision, device, before.Running.Interfaces, running.Interfaces)
	}
	if len(running.Interfaces) != 1 || running.Interfaces[0].Name != device {
		t.Fatalf("startup changed row identity: %+v", running.Interfaces)
	}
}
