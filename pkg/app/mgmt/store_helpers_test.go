// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

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

func TestOpenStoreWithRetrySucceedsAfterFailures(t *testing.T) {
	oldSleep := storeOpenSleep
	t.Cleanup(func() { storeOpenSleep = oldSleep })
	var delays []time.Duration
	storeOpenSleep = func(delay time.Duration) { delays = append(delays, delay) }

	failures := 2
	got, err := openStoreWithRetry("test", func() (string, error) {
		if failures > 0 {
			failures--
			return "", errors.New("temporary open failure")
		}
		return "opened", nil
	})
	if err != nil {
		t.Fatalf("openStoreWithRetry() error = %v", err)
	}
	if got != "opened" {
		t.Fatalf("openStoreWithRetry() = %q, want %q", got, "opened")
	}
	wantDelays := []time.Duration{200 * time.Millisecond, 400 * time.Millisecond}
	if len(delays) != len(wantDelays) {
		t.Fatalf("sleep called %d times, want %d", len(delays), len(wantDelays))
	}
	for i := range wantDelays {
		if delays[i] != wantDelays[i] {
			t.Errorf("sleep delay %d = %s, want %s", i, delays[i], wantDelays[i])
		}
	}
}

func TestOpenStoreWithRetryExhaustsAttempts(t *testing.T) {
	oldSleep := storeOpenSleep
	t.Cleanup(func() { storeOpenSleep = oldSleep })
	var delays []time.Duration
	storeOpenSleep = func(delay time.Duration) { delays = append(delays, delay) }

	wantErr := errors.New("persistent open failure")
	attempts := 0
	_, err := openStoreWithRetry("test", func() (string, error) {
		attempts++
		return "", wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("openStoreWithRetry() error = %v, want %v", err, wantErr)
	}
	if attempts != storeOpenMaxAttempts {
		t.Fatalf("open called %d times, want %d", attempts, storeOpenMaxAttempts)
	}
	wantDelays := []time.Duration{200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond, 2 * time.Second}
	if len(delays) != len(wantDelays) {
		t.Fatalf("sleep called %d times, want %d", len(delays), len(wantDelays))
	}
	for i := range wantDelays {
		if delays[i] != wantDelays[i] {
			t.Errorf("sleep delay %d = %s, want %s", i, delays[i], wantDelays[i])
		}
	}
}

func TestOpenStoreWithRetryFirstAttemptDoesNotSleep(t *testing.T) {
	oldSleep := storeOpenSleep
	t.Cleanup(func() { storeOpenSleep = oldSleep })
	oldWarnf := storeOpenWarnf
	t.Cleanup(func() { storeOpenWarnf = oldWarnf })
	sleeps := 0
	warnings := 0
	storeOpenSleep = func(time.Duration) { sleeps++ }
	storeOpenWarnf = func(string, ...any) { warnings++ }

	got, err := openStoreWithRetry("test", func() (string, error) { return "opened", nil })
	if err != nil {
		t.Fatalf("openStoreWithRetry() error = %v", err)
	}
	if got != "opened" {
		t.Fatalf("openStoreWithRetry() = %q, want %q", got, "opened")
	}
	if sleeps != 0 {
		t.Fatalf("sleep called %d times, want 0", sleeps)
	}
	if warnings != 0 {
		t.Fatalf("warn logged %d times, want 0", warnings)
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
