// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func captureBootstrapStdout(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = file
	t.Cleanup(func() { os.Stdout = previous; file.Close() })
	return file
}

func readBootstrapFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestBootstrapDeliverySnapshot(t *testing.T) {
	stdout := captureBootstrapStdout(t)
	dir := t.TempDir()
	ledger := &users.BootstrapLedger{}
	delivery := newBootstrapDelivery(zap.NewNop().Sugar(), filepath.Join(dir, "users.db"), ledger)
	// Replace stale material from an earlier boot rather than reading it.
	if err := os.MkdirAll(filepath.Dir(delivery.path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(delivery.path, []byte("stale old-password\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	alice := users.BootstrapEvent{Kind: users.BootstrapIssued, UserID: "a", Username: "alice", Password: "alice-private", Generation: 2, Reason: "reissue"}
	bob := users.BootstrapEvent{Kind: users.BootstrapIssued, UserID: "b", Username: "bob", Password: "bob-private", Generation: 1, Reason: "rotate"}
	delivery.observe(bob)
	delivery.observe(alice)
	if got := readBootstrapFile(t, delivery.path); got != "alice alice-private\nbob bob-private\n" {
		t.Fatalf("unexpected snapshot %q", got)
	}
	for path, mode := range map[string]os.FileMode{filepath.Dir(delivery.path): 0o700, delivery.path: 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("permissions for %s: %v, %v", path, info, err)
		}
	}
	delivery.observe(users.BootstrapEvent{Kind: users.BootstrapRetired, UserID: "a", Username: "alice"})
	if got := readBootstrapFile(t, delivery.path); got != "bob bob-private\n" {
		t.Fatalf("retired password remains: %q", got)
	}
	// Factory reset replaces all accounts, not just the named admin.
	delivery.observe(users.BootstrapEvent{Kind: users.BootstrapIssued, UserID: "c", Username: "admin", Password: "reset-private", Generation: 1, Reason: "reset"})
	if got := readBootstrapFile(t, delivery.path); got != "admin reset-private\n" {
		t.Fatalf("reset retained an old account: %q", got)
	}
	delivery.observe(users.BootstrapEvent{Kind: users.BootstrapRetired, UserID: "c", Username: "admin"})
	if got := readBootstrapFile(t, delivery.path); got != "" {
		t.Fatalf("last retirement left a password: %q", got)
	}
	got := readBootstrapFile(t, stdout.Name())
	want := "CONTAIND ONE-TIME PASSWORD user=alice password=alice-private generation=2 (a password change is required at first login)\n"
	if !strings.Contains(got, want) || strings.Count(got, "CONTAIND ONE-TIME PASSWORD") != 3 {
		t.Fatalf("unexpected stdout delivery: %q", got)
	}
	metadata := ledger.Drain()
	if len(metadata) != 3 || metadata[0].Username != "bob" || metadata[1].Generation != 2 || metadata[2].Reason != "reset" || ledger.Drain() != nil {
		t.Fatalf("unexpected ledger: %+v", metadata)
	}
}

func TestBootstrapNoLeakZapTeeAndSlogBridge(t *testing.T) {
	stdout := captureBootstrapStdout(t)
	var cores []zapcore.Core
	sinks := map[string]*observer.ObservedLogs{}
	for _, name := range []string{"stdout", "file", "syslog"} {
		core, logs := observer.New(zapcore.DebugLevel)
		cores = append(cores, core)
		sinks[name] = logs
	}
	logger := zap.New(zapcore.NewTee(cores...))
	previous := slog.Default()
	logging.InstallSlogBridge(logger)
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.Warn("slog bridge sentinel")

	// A non-directory delivery path forces the normal-log warning path.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bootstrap"), []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger := &users.BootstrapLedger{}
	delivery := newBootstrapDelivery(logger.Sugar(), filepath.Join(dir, "users.db"), ledger)
	const secret = "unique-bootstrap-secret-not-for-any-log"
	delivery.observe(users.BootstrapEvent{
		Kind: users.BootstrapIssued, UserID: "id", Username: "admin",
		Password: secret, Generation: 7, Reason: "seed",
	})
	if !strings.Contains(readBootstrapFile(t, stdout.Name()), "password="+secret) {
		t.Fatal("password did not reach direct stdout")
	}
	store, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := auditBootstrapDelivery(context.Background(), store, ledger); err != nil {
		t.Fatal(err)
	}
	records, err := store.List(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Action != "auth.bootstrap_password.issued" || records[0].Target != "admin" || records[0].Detail != "generation=7 reason=seed" {
		t.Fatalf("unexpected audit records: %+v", records)
	}
	data, err := json.Marshal(records)
	if err != nil || strings.Contains(string(data), secret) {
		t.Fatalf("audit leaked a password: %s, %v", data, err)
	}
	for name, logs := range sinks {
		if logs.FilterMessage("slog bridge sentinel").Len() != 1 || logs.FilterMessageSnippet("stdout remains authoritative").Len() != 1 {
			t.Fatalf("%s did not exercise bridge and warning paths: %+v", name, logs.All())
		}
		for _, entry := range logs.All() {
			if strings.Contains(entry.Message, secret) || strings.Contains(fmt.Sprint(entry.ContextMap()), secret) {
				t.Fatalf("password reached the %s logger core", name)
			}
		}
	}
}

func TestBootstrapSnapshotRejectsSymlinkDirectory(t *testing.T) {
	captureBootstrapStdout(t)
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "bootstrap")); err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zapcore.DebugLevel)
	delivery := newBootstrapDelivery(zap.New(core).Sugar(), filepath.Join(dir, "users.db"), &users.BootstrapLedger{})
	delivery.observe(users.BootstrapEvent{Kind: users.BootstrapIssued, UserID: "id", Username: "admin", Password: "private"})
	if _, err := os.Stat(filepath.Join(outside, "admin-password")); !os.IsNotExist(err) {
		t.Fatalf("snapshot followed a symlink: %v", err)
	}
	if logs.FilterMessageSnippet("stdout remains authoritative").Len() != 1 {
		t.Fatal("missing file delivery warning")
	}
}
