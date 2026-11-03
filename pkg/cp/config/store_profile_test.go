// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/profile"
)

func TestProfileWritesCandidateRollback(t *testing.T) {
	if os.Getenv("CONTAIND_TEST_PROFILE_STORE") != "1" {
		t.Setenv(profile.EnvVar, "strict")
		t.Setenv("CONTAIND_TEST_PROFILE_STORE", "1")
		cmd := exec.Command(os.Args[0], "-test.run=^TestProfileWritesCandidateRollback$", "-test.v")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	ctx := context.Background()
	open := func() *SQLiteStore {
		t.Helper()
		s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	weak := func() *Config {
		cfg := DefaultConfig()
		off := false
		cfg.System.SSH.ShellMode = SSHShellModeLinux
		cfg.System.Mgmt.EnableHTTPS, cfg.System.Mgmt.EnableHSTS = &off, &off
		return cfg
	}
	// Prepare training-era saved state before loading the immutable strict
	// process profile. Reads and writes must continue to use unprojected intent.
	store, promotion := open(), open()
	if err := store.Save(ctx, weak()); err != nil {
		t.Fatal(err)
	}
	if err := promotion.Save(ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if _, err := promotion.SaveCandidate(ctx, testBaseRevision(promotion, ctx), weak()); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.Load(); err != nil {
		t.Fatal(err)
	}
	refused := func(err error, field string) {
		t.Helper()
		var invalid *ValidationError
		if !errors.As(err, &invalid) || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "CONTAIND_PROFILE=strict") {
			t.Fatalf("want %s profile refusal, got %v", field, err)
		}
	}
	_, err := promotion.Commit(ctx, testBaseRevision(promotion, ctx))
	refused(err, "ssh.shellMode")
	// Both full replacement and mutation permit unchanged weak saved values.
	carried := weak()
	carried.Description = "unrelated edit"
	if _, err := store.SaveCandidate(ctx, testBaseRevision(store, ctx), carried); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MutateCandidate(ctx, testBaseRevision(store, ctx), func(cfg *Config) error {
		cfg.Description = "another edit"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, testBaseRevision(store, ctx)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"ssh.shellMode", "mgmt.enableHTTPS", "mgmt.enableHSTS"} {
		t.Run(field, func(t *testing.T) {
			old, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			repair := func(cfg *Config) error {
				on := true
				switch field {
				case "ssh.shellMode":
					cfg.System.SSH.ShellMode = SSHShellModeAppliance
				case "mgmt.enableHTTPS":
					cfg.System.Mgmt.EnableHTTPS = &on
				case "mgmt.enableHSTS":
					cfg.System.Mgmt.EnableHSTS = &on
				}
				return nil
			}
			if _, err := store.MutateCandidate(ctx, testBaseRevision(store, ctx), repair); err != nil {
				t.Fatal(err)
			}
			// A repair in the candidate is not running yet. Reverting that
			// draft is allowed; validation must not use the previous candidate.
			if _, err := store.SaveCandidate(ctx, testBaseRevision(store, ctx), old); err != nil {
				t.Fatal(err)
			}
			if _, err := store.MutateCandidate(ctx, testBaseRevision(store, ctx), repair); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Commit(ctx, testBaseRevision(store, ctx)); err != nil {
				t.Fatal(err)
			}
			before := testBaseRevision(store, ctx)
			_, err = store.SaveCandidate(ctx, before, old)
			refused(err, field)
			if testBaseRevision(store, ctx) != before {
				t.Fatal("refused write advanced revision")
			}
			refused(store.Save(ctx, old), field)
			_, err = store.MutateCandidate(ctx, before, func(cfg *Config) error {
				cfg.System.SSH.ShellMode = old.System.SSH.ShellMode
				cfg.System.Mgmt.EnableHTTPS = old.System.Mgmt.EnableHTTPS
				cfg.System.Mgmt.EnableHSTS = old.System.Mgmt.EnableHSTS
				return nil
			})
			refused(err, field)
			// Recovery restores previously accepted weak intent. Runtime
			// projection, never persistence, enforces the strict invariants.
			if _, err := store.Rollback(ctx, before); err != nil {
				t.Fatalf("rollback of carried values: %v", err)
			}
			if _, err := store.MutateCandidate(ctx, testBaseRevision(store, ctx), repair); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Commit(ctx, testBaseRevision(store, ctx)); err != nil {
				t.Fatal(err)
			}
		})
	}
	fresh := open()
	refused(fresh.Save(ctx, weak()), "ssh.shellMode")
	refused(fresh.ValidateConfig(weak()), "ssh.shellMode")
	if err := fresh.Save(ctx, DefaultConfig()); err != nil {
		t.Fatalf("factory defaults: %v", err)
	}
}
