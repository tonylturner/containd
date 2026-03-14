// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestResolveSSHRuntimeConfigAndHelpers(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.System.SSH.ListenAddr = ":3022"
	cfg.System.SSH.AuthorizedKeysDir = "/cfg/keys"
	cfg.System.SSH.AllowPassword = true
	cfg.System.SSH.Banner = "authorized use only"
	cfg.System.SSH.HostKeyRotationDays = 14

	t.Setenv("CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY", "ssh-ed25519 AAAATEST")
	t.Setenv("CONTAIND_SSH_BOOTSTRAP_ADMIN_USER", "admin")
	rt := resolveSSHRuntimeConfig(cfg, "10.10.10.10:8080", "127.0.0.1:8080")
	if rt.sshAddr != ":3022" || rt.authKeysDir != "/cfg/keys" {
		t.Fatalf("unexpected ssh runtime config: %+v", rt)
	}
	if rt.bootstrapUser != "admin" || rt.bootstrapKey == "" {
		t.Fatalf("unexpected bootstrap config: %+v", rt)
	}
	if rt.baseURL != "http://127.0.0.1:8080" {
		t.Fatalf("baseURL = %q", rt.baseURL)
	}
	if !rt.allowPassword {
		t.Fatal("expected allowPassword=true from config")
	}
}

func TestResolveSSHAllowPasswordAndBootstrap(t *testing.T) {
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
	if !resolveSSHAllowPassword(cfg, emptyDir) {
		t.Fatal("expected bootstrap keys path to allow password auth")
	}
	cfg.System.SSH.AllowPassword = true
	if !resolveSSHAllowPassword(cfg, keysDir) {
		t.Fatal("expected explicit config allowPassword to win")
	}
	t.Setenv("CONTAIND_SSH_ALLOW_PASSWORD", "false")
	if resolveSSHAllowPassword(cfg, keysDir) {
		t.Fatal("expected env override to disable password auth")
	}
}

func TestResolveSSHBaseURL(t *testing.T) {
	if got := resolveSSHBaseURL("10.10.10.10:8080", "127.0.0.1:8080"); got != "http://127.0.0.1:8080" {
		t.Fatalf("resolveSSHBaseURL loopback = %q", got)
	}
	if got := resolveSSHBaseURL("0.0.0.0:8081", ""); got != "http://127.0.0.1:8081" {
		t.Fatalf("resolveSSHBaseURL inferred = %q", got)
	}
	if got := resolveSSHBaseURL("", ""); got != "http://127.0.0.1:8080" {
		t.Fatalf("resolveSSHBaseURL default = %q", got)
	}
}
