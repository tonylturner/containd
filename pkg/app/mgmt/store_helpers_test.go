// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestStoreHelperPrimitives(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	if v := boolPtr(true); v == nil || !*v {
		t.Fatal("boolPtr(true) did not return a true pointer")
	}
	if !boolDefault(nil, true) {
		t.Fatal("boolDefault(nil, true) should return default")
	}
	if boolDefault(boolPtr(false), true) {
		t.Fatal("boolDefault(false, true) should return false")
	}
	if got := cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.EnableHTTP }); got != nil {
		t.Fatalf("cfgGetBool = %v, want nil", got)
	}
	if got := cfgGetInt(nil, func(c *config.Config) int { return c.System.Mgmt.HSTSMaxAgeSeconds }, 5); got != 5 {
		t.Fatalf("cfgGetInt = %d, want 5", got)
	}
}

func TestMustInitStores(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CONTAIND_CONFIG_DB", filepath.Join(tmp, "config", "config.db"))
	t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(tmp, "audit", "audit.db"))
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(tmp, "users", "users.db"))

	cfgStore := mustInitStore()
	if err := cfgStore.Save(context.Background(), config.DefaultConfig()); err != nil {
		t.Fatalf("config store save: %v", err)
	}
	_ = cfgStore.Close()

	auditStore := mustInitAuditStore()
	if err := auditStore.Add(context.Background(), auditRecordForTest()); err != nil {
		t.Fatalf("audit store add: %v", err)
	}
	_ = auditStore.Close()

	usersStore := mustInitUsersStore()
	if err := usersStore.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatalf("users store ensure default admin: %v", err)
	}
	_ = usersStore.Close()
}

func auditRecordForTest() audit.Record {
	return audit.Record{Actor: "test", Source: "unit", Action: "write", Target: "db", Result: "ok"}
}
