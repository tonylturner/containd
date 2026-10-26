// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
	"golang.org/x/crypto/ssh"
)

func TestResolveSSHRuntimeConfigAndHelpers(t *testing.T) {
	t.Setenv("CONTAIND_SSH_ALLOW_PASSWORD", "")
	cfg := config.DefaultConfig()
	cfg.System.SSH.ListenAddr = ":3022"
	cfg.System.SSH.AuthorizedKeysDir = "/cfg/keys"
	cfg.System.SSH.AllowPassword = new(true)
	cfg.System.SSH.Banner = "authorized use only"
	cfg.System.SSH.HostKeyRotationDays = 14

	t.Setenv("CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY", "ssh-ed25519 AAAATEST")
	t.Setenv("CONTAIND_SSH_BOOTSTRAP_ADMIN_USER", "admin")
	rt := resolveSSHRuntimeConfig(cfg)
	if rt.sshAddr != ":3022" || rt.authKeysDir != "/cfg/keys" {
		t.Fatalf("unexpected ssh runtime config: %+v", rt)
	}
	if rt.bootstrapUser != "admin" || rt.bootstrapKey == "" {
		t.Fatalf("unexpected bootstrap config: %+v", rt)
	}
	if !rt.allowPassword {
		t.Fatal("expected allowPassword=true from config")
	}
}

func TestSSHDisableStageAndCommitAdminKeyGuard(t *testing.T) {
	ctx := context.Background()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	userStore, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer userStore.Close()
	if err := userStore.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := userStore.Create(ctx, users.User{Username: "viewer", Role: "view"}, "ViewerPassword1"); err != nil {
		t.Fatal(err)
	}
	configureSSHPolicy(store, userStore)
	cfg := config.DefaultConfig()
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	keys := t.TempDir()
	t.Setenv("CONTAIND_SSH_AUTH_KEYS_DIR", keys)
	cfg.System.SSH.AllowPassword = new(false)
	if err := store.SaveCandidate(ctx, cfg); err == nil {
		t.Fatal("stage accepted without a key")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	key := ssh.MarshalAuthorizedKey(pub)
	if err := os.WriteFile(filepath.Join(keys, "viewer.pub"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCandidate(ctx, cfg); err == nil {
		t.Fatal("viewer key allowed an admin lockout")
	}
	adminKey := filepath.Join(keys, "containd.pub")
	if err := os.WriteFile(adminKey, []byte("not an SSH key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCandidate(ctx, cfg); err == nil {
		t.Fatal("malformed key allowed an admin lockout")
	}
	if err := os.WriteFile(adminKey, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCandidate(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	// Make the key unreadable to the parser after staging, without depending
	// on permission enforcement (tests may run as root).
	if err := os.WriteFile(adminKey, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx); err == nil {
		t.Fatal("commit failed to recheck admin keys")
	}
	if err := os.WriteFile(adminKey, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestResolveSSHAllowPasswordAndBootstrap(t *testing.T) {
	t.Setenv("CONTAIND_SSH_ALLOW_PASSWORD", "")
	tmp := t.TempDir()
	keysDir := filepath.Join(tmp, "keys")
	emptyDir := filepath.Join(tmp, "empty")

	if !authKeysDirNeedsBootstrap(keysDir) {
		t.Fatal("missing keys dir should need bootstrap")
	}
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatalf("MkdirAll emptyDir: %v", err)
	}
	if !authKeysDirNeedsBootstrap(emptyDir) {
		t.Fatal("empty keys dir should need bootstrap")
	}
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "containd.pub"), []byte("ssh-ed25519 AAAATEST"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if authKeysDirNeedsBootstrap(keysDir) {
		t.Fatal("populated keys dir should not need bootstrap")
	}

	cfg := &config.Config{}
	t.Setenv("CONTAIND_LAB_MODE", "0")
	if !sshPasswordAllowedForTest(cfg, emptyDir) {
		t.Fatal("expected bootstrap keys path to allow password auth")
	}
	if sshPasswordAllowedForTest(cfg, keysDir) {
		t.Fatal("unset with populated keys must not bootstrap outside lab mode")
	}
	cfg.System.SSH.AllowPassword = new(true)
	if !sshPasswordAllowedForTest(cfg, keysDir) {
		t.Fatal("expected explicit config allowPassword to win")
	}
	cfg.System.SSH.AllowPassword = new(false)
	t.Setenv("CONTAIND_SSH_ALLOW_PASSWORD", "true")
	if sshPasswordAllowedForTest(cfg, keysDir) {
		t.Fatal("expected explicit disable to override the environment")
	}
}

func TestSSHPasswordDefaultsAndExplicitDisable(t *testing.T) {
	for _, lab := range []string{"0", "1"} {
		t.Run("lab="+lab, func(t *testing.T) {
			t.Setenv("CONTAIND_LAB_MODE", lab)
			unreadable := filepath.Join(t.TempDir(), "not-a-directory")
			if err := os.WriteFile(unreadable, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{t.TempDir(), unreadable, filepath.Join(t.TempDir(), "missing")} {
				t.Setenv("CONTAIND_SSH_ALLOW_PASSWORD", "")
				cfg := config.DefaultConfig()
				if !sshPasswordAllowedForTest(cfg, dir) {
					t.Fatal("unset must retain bootstrap behavior")
				}
				cfg.System.SSH.AllowPassword = new(false)
				t.Setenv("CONTAIND_SSH_ALLOW_PASSWORD", "true")
				if sshPasswordAllowedForTest(cfg, dir) {
					t.Fatal("explicit disable must hold")
				}
			}
		})
	}
}

func TestSSHRuntimePolicyReportsEnvironmentSource(t *testing.T) {
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.DefaultConfig()
	cfg.System.SSH.AllowPassword = new(true)
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	configureSSHPolicy(store, nil)
	t.Setenv("CONTAIND_SSH_ALLOW_PASSWORD", "0")
	policy, err := store.SSHRuntimePolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if policy.AllowPassword || policy.PasswordSource != "environment (CONTAIND_SSH_ALLOW_PASSWORD)" {
		t.Fatalf("effective environment override not reported: %+v", policy)
	}
	// Boot must honor a persisted disable independently of stage validation.
	cfg.System.SSH.AllowPassword = new(false)
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_SSH_ALLOW_PASSWORD", "true")
	policy, err = store.SSHRuntimePolicy(context.Background())
	if err != nil || policy.AllowPassword || policy.PasswordSource != "config" {
		t.Fatalf("environment overrode persisted disable: %+v, %v", policy, err)
	}
}

func sshPasswordAllowedForTest(cfg *config.Config, dir string) bool {
	allow, _ := resolveSSHPasswordPolicy(cfg, dir)
	return allow
}
