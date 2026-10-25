// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func TestReservedBootPreflightPrecedesRepairsAndUsers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.db")
	t.Setenv("CONTAIND_CONFIG_DB", path)
	t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(dir, "audit.db"))
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(dir, "users.db"))
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "lan3", Device: "reserved-test", Zone: "lan"}}
	// Missing backfill values are repairable; disabled enforcement is not.
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.MutateCandidate(ctx, func(c *config.Config) error {
		c.Description = "staged edit must survive failed boot"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	r := &mgmtpath.Reservation{Device: "reserved-test", Local: netip.MustParsePrefix("10.99.99.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: 8080}
	_, _, err = initMgmtStores(zap.NewNop().Sugar(), r)
	if err == nil || !strings.Contains(err.Error(), "reserved management path") {
		t.Fatalf("unsafe boot accepted: %v", err)
	}
	for _, name := range []string{"users.db", "audit.db"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s created before preflight: %v", name, err)
		}
	}
	store, err = config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	running, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := store.LoadCandidate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if running.System.Hostname != "" || running.System.Mgmt.HTTPListenAddr != "" || candidate.Description != "staged edit must survive failed boot" {
		t.Fatal("failed preflight repaired running or lost staged work")
	}
}
