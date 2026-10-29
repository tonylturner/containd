// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func TestStoredDNP3UnitIDBootsIntoRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.db")
	t.Setenv("CONTAIND_CONFIG_DB", path)
	t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(dir, "audit.db"))
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(dir, "users.db"))
	ctx := context.Background()
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Save(ctx, config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// Model every snapshot written before unitId capability validation existed.
	want := []config.Rule{{
		ID: "legacy-unit", Action: config.ActionAllow,
		ICS: config.ICSPredicate{Protocol: "dnp3", UnitID: new(uint8(0)), Mode: "learn"},
	}}
	setStoredRules(t, path, want)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, key := range []string{"candidate", "previous"} {
		if _, err := db.Exec(`INSERT OR REPLACE INTO configs (key,data,updated_at) SELECT ?,data,updated_at FROM configs WHERE key='running'`, key); err != nil {
			t.Fatal(err)
		}
	}

	stores, running, err := initMgmtStores(zap.NewNop().Sugar(), nil)
	if err != nil {
		t.Fatalf("stored unitId stopped management before recovery: %v", err)
	}
	defer stores.store.Close()
	defer stores.auditStore.Close()
	defer stores.userStore.Close()
	candidate, err := stores.store.LoadCandidate(ctx)
	if err != nil {
		t.Fatalf("candidate no longer loads: %v", err)
	}
	for _, cfg := range []*config.Config{running, candidate} {
		if !reflect.DeepEqual(cfg.Firewall.Rules, want) {
			t.Fatalf("boot rewrote unitId: %+v", cfg.Firewall.Rules)
		}
	}
	for _, key := range []string{"running", "candidate", "previous"} {
		var raw []byte
		if err := db.QueryRow(`SELECT data FROM configs WHERE key=?`, key).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var cfg config.Config
		if err := json.Unmarshal(raw, &cfg); err != nil || !reflect.DeepEqual(cfg.Firewall.Rules, want) {
			t.Fatalf("%s lost stored unitId: %+v %v", key, cfg.Firewall.Rules, err)
		}
	}
	const cause = "rule legacy-unit ics unitId is not supported for protocol dnp3"
	fault, err := config.ManagementBootFaultForStore(ctx, stores.store)
	if err != nil || !strings.Contains(fault, cause) {
		t.Fatalf("recovery lost validation cause: %q %v", fault, err)
	}
	if err := config.CheckManagementBootFault(ctx, stores.store); !errors.Is(err, config.ErrManagementBootFault) {
		t.Fatalf("invalid running config is not gated: %v", err)
	}
	if stores.bootEvent == nil || stores.bootEvent.Kind != "management.recovery.boot_fault" {
		t.Fatalf("boot did not enter recovery: %+v", stores.bootEvent)
	}
	eventCause, _ := stores.bootEvent.Attributes["error"].(string)
	if !strings.Contains(eventCause, cause) {
		t.Fatalf("recovery event lost unitId cause: %q", eventCause)
	}
	// The previous snapshot also decodes through the store's rollback path;
	// it is rejected semantically rather than erasing the unsupported filter.
	if err := stores.store.Rollback(ctx); err == nil || !strings.Contains(err.Error(), cause) {
		t.Fatalf("previous snapshot did not reach semantic validation: %v", err)
	}
}
