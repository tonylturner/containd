// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// A shellMode stored by a release that did not validate it boots normally,
// not into management recovery, and runs the mode that release ran.
func TestStoredUnvalidatedShellModeBootsNormally(t *testing.T) {
	for stored, want := range map[string]string{"Linux": "linux", "bash": "appliance"} {
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
		if err := store.Save(ctx, config.DefaultConfig()); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		setStoredShellMode(t, path, stored)

		stores, running, err := initMgmtStores(zap.NewNop().Sugar(), nil)
		if err != nil {
			t.Fatalf("stored %q stopped management: %v", stored, err)
		}
		if err := config.CheckManagementBootFault(ctx, stores.store); errors.Is(err, config.ErrManagementBootFault) {
			t.Fatalf("stored %q booted into recovery: %v", stored, err)
		}
		if running.System.SSH.ShellMode != want {
			t.Fatalf("stored %q runs %q, want %q", stored, running.System.SSH.ShellMode, want)
		}
		_ = stores.store.Close()
		_ = stores.auditStore.Close()
		_ = stores.userStore.Close()
	}
}

func setStoredShellMode(t *testing.T, path, mode string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw string
	if err := db.QueryRow(`SELECT data FROM configs WHERE key = 'running'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	doc["system"].(map[string]any)["ssh"].(map[string]any)["shellMode"] = mode
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE configs SET data = ? WHERE key = 'running'`, string(body)); err != nil {
		t.Fatal(err)
	}
}
