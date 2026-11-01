// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func TestStartupRepairsPreserveCandidateAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.db")
	t.Setenv("CONTAIND_CONFIG_DB", path)
	t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(dir, "audit.db"))
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(dir, "users.db"))
	ctx := context.Background()
	initial := &config.Config{
		System:     config.SystemConfig{Hostname: "running"},
		Zones:      []config.Zone{{Name: "wan"}},
		Interfaces: []config.Interface{{Name: "wan", Zone: "wan", Device: "stale-device"}},
		IDS:        config.IDSConfig{Rules: config.DefaultIDSConfig().Rules[:1]},
	}
	wantDevice := startupRepairDevice(t, initial)
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
		if cfg.Interfaces[0].Device != wantDevice || cfg.System.Mgmt.HTTPListenAddr != ":8080" {
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
	if err != nil || promoted.Interfaces[0].Device != wantDevice || promoted.System.Mgmt.HTTPListenAddr != ":8080" || promoted.System.Hostname != "staged-host" {
		t.Fatalf("commit reverted startup repair: %+v %v", promoted, err)
	}
}

// Exercise the real startup autobinder against a local, IPv4-bearing device.
// This needs no network mutation, privileged access or fixed host device names.
func startupRepairDevice(t *testing.T, initial *config.Config) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			ip, subnet, err := net.ParseCIDR(addr.String())
			if err != nil || ip.To4() == nil {
				continue
			}
			t.Setenv("CONTAIND_AUTO_WAN_SUBNET", subnet.String())
			probe := *initial
			probe.Interfaces = append([]config.Interface(nil), initial.Interfaces...)
			blankDefaultInterfaceDevices(&probe)
			if httpapi.AutoBindDefaultInterfaceDevices(&probe) {
				return probe.Interfaces[0].Device
			}
		}
	}
	t.Fatal("startup autobind integration test needs an eligible local IPv4 interface")
	return ""
}
