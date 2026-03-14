// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"os"
	"path/filepath"

	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func boolPtr(v bool) *bool { return &v }

func boolDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func cfgGetBool(cfg *config.Config, f func(*config.Config) *bool) *bool {
	if cfg == nil {
		return nil
	}
	return f(cfg)
}

func cfgGetInt(cfg *config.Config, f func(*config.Config) int, def int) int {
	if cfg == nil {
		return def
	}
	return f(cfg)
}

func mustInitStore() config.Store {
	dbPath := common.Env("CONTAIND_CONFIG_DB", filepath.Join("data", "config.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		logging.NewService("mgmt").Fatalf("failed to create config dir: %v", err)
	}
	store, err := config.NewSQLiteStore(dbPath)
	if err != nil {
		logging.NewService("mgmt").Fatalf("failed to open config store: %v", err)
	}
	return store
}

func mustInitAuditStore() audit.Store {
	dbPath := common.Env("CONTAIND_AUDIT_DB", filepath.Join("data", "audit.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		logging.NewService("mgmt").Fatalf("failed to create audit dir: %v", err)
	}
	store, err := audit.NewSQLiteStore(dbPath)
	if err != nil {
		logging.NewService("mgmt").Fatalf("failed to open audit store: %v", err)
	}
	return store
}

func mustInitUsersStore() users.Store {
	dbPath := common.Env("CONTAIND_USERS_DB", filepath.Join("data", "users.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		fallback := filepath.Join("data", "users.db")
		if fallback != dbPath {
			_ = os.MkdirAll(filepath.Dir(fallback), 0o755)
			logging.NewService("mgmt").Warnf("users db path %s not writable (%v); falling back to %s", dbPath, err, fallback)
			dbPath = fallback
		} else {
			logging.NewService("mgmt").Fatalf("failed to create users dir: %v", err)
		}
	}
	store, err := users.NewSQLiteStore(dbPath)
	if err != nil {
		logging.NewService("mgmt").Fatalf("failed to open users store: %v", err)
	}
	return store
}
