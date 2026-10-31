// SPDX-License-Identifier: Apache-2.0
package services

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func openVPNFakeManager(t *testing.T) (*VPNManager, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", filepath.Join(root, "authority with spaces"))
	starts := filepath.Join(root, "starts")
	script := filepath.Join(root, "openvpn")
	// All daemon references are read relative to the daemon cwd, before ready.
	// Missing files abort startup; merely finding the config is insufficient.
	body := `#!/bin/sh
set -eu
trap 'exit 0' TERM INT
[ "$1" = '--config' ]
while read -r option file rest; do
 case "$option" in
 ca|cert|key|tls-auth|tls-crypt|auth-user-pass|crl-verify)
  cat "$file" >/dev/null || exit 9
  ;;
 esac
done < "$2"
printf '%s\n' "$$" >> '` + starts + `'
echo 'Initialization Sequence Completed'
while true; do sleep 0.02; done
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	m := NewVPNManager(filepath.Join(root, "services"))
	m.OpenVPNPath = script
	m.SuperviseOpenVPN = true
	m.log = zap.NewNop().Sugar()
	t.Cleanup(func() { m.applyMu.Lock(); defer m.applyMu.Unlock(); _ = m.stopOpenVPN() })
	return m, starts
}
func openVPNStarts(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return len(strings.Fields(string(b)))
}
func openVPNApply(t *testing.T, m *VPNManager, cfg config.VPNConfig) {
	t.Helper()
	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}
func openVPNServerConfig() config.VPNConfig {
	return config.VPNConfig{OpenVPN: config.OpenVPNConfig{Enabled: true, Mode: "server", Server: &config.OpenVPNManagedServerConfig{TunnelCIDR: "10.8.0.0/24", PublicEndpoint: "vpn.example.test"}}}
}

func TestOpenVPNMaterialRevisionLifecycle(t *testing.T) {
	m, starts := openVPNFakeManager(t)
	cfg := config.VPNConfig{OpenVPN: config.OpenVPNConfig{Enabled: true, Managed: &config.OpenVPNManagedClientConfig{Remote: "vpn.example.test", CA: "ca", Cert: "cert", Key: "key", Username: "alice", Password: testCredential("initial")}}}
	openVPNApply(t, m, cfg)
	openVPNApply(t, m, cfg)
	if got := openVPNStarts(t, starts); got != 1 {
		t.Fatalf("no-op restarted: %d", got)
	}
	for n, change := range []func(){func() { cfg.OpenVPN.Managed.Key = "new-key" }, func() { cfg.OpenVPN.Managed.Password = testCredential("changed") }, func() { cfg.OpenVPN.Managed.Remote = "other.example.test" }} {
		change()
		openVPNApply(t, m, cfg)
		openVPNApply(t, m, cfg)
		if got := openVPNStarts(t, starts); got != n+2 {
			t.Fatalf("changed material restarts: %d want %d", got, n+2)
		}
	}
	// Imported ConfigPath is never executed directly, including same-path edits.
	source := filepath.Join(t.TempDir(), "source.ovpn")
	profile := "client\nremote vpn.example.test 1194\n<ca>\nca\n</ca>\n"
	if err := os.WriteFile(source, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.OpenVPN = config.OpenVPNConfig{Enabled: true, ConfigPath: source}
	openVPNApply(t, m, cfg)
	active := m.Status()["openvpn_config_path"].(string)
	if active == source || !filepath.IsAbs(active) {
		t.Fatalf("unowned runtime path: %s", active)
	}
	if err := os.WriteFile(source, []byte(profile+"verb 4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	openVPNApply(t, m, cfg)
	openVPNApply(t, m, cfg)
	if got := openVPNStarts(t, starts); got != 6 {
		t.Fatalf("same-path profile not restarted once: %d", got)
	}
	before, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(profile+"up /tmp/evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var typed *config.ServiceConfigError
	if err := m.Apply(context.Background(), cfg); !errors.As(err, &typed) {
		t.Fatalf("untyped unsafe profile: %v", err)
	}
	after, err := os.ReadFile(active)
	if err != nil || !bytes.Equal(before, after) || openVPNStarts(t, starts) != 6 {
		t.Fatalf("refusal touched active files/process: %v", err)
	}
}

func TestOpenVPNRevokeRuntimeAndRollback(t *testing.T) {
	m, starts := openVPNFakeManager(t)
	cfg := openVPNServerConfig()
	openVPNApply(t, m, cfg)
	alice, err := m.CreateOpenVPNClient(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := m.CreateOpenVPNClient(context.Background(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	invPath := filepath.Join(openVPNManagedServerDir(), "pki", "inventory.json")
	before, err := os.ReadFile(invPath)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := m.DownloadOpenVPNClient(context.Background(), alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOpenVPNProfile(profile); err != nil {
		t.Fatalf("download violates import grammar: %v", err)
	}
	if _, err := m.DownloadOpenVPNClient(context.Background(), "missing"); err == nil {
		t.Fatal("unknown download issued a certificate")
	}
	after, err := os.ReadFile(invPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("download mutated authority: %v", err)
	}
	result, err := m.RevokeOpenVPNClient(context.Background(), alice.ID)
	if err != nil || !result.Revoked || !result.Applied {
		t.Fatalf("revoke: %+v %v", result, err)
	}
	if openVPNStarts(t, starts) != 2 {
		t.Fatal("revoke did not restart exactly once")
	}
	result, err = m.RevokeOpenVPNClient(context.Background(), alice.ID)
	if err != nil || !result.Applied || openVPNStarts(t, starts) != 2 {
		t.Fatalf("idempotent revoke restarted: %+v %v", result, err)
	}
	if _, err := m.DownloadOpenVPNClient(context.Background(), alice.ID); err == nil {
		t.Fatal("revoked download accepted")
	}
	// An old config snapshot is deliberately reapplied after revocation.
	openVPNApply(t, m, cfg)
	inv, err := readOpenVPNInventory(filepath.Dir(invPath))
	if err != nil {
		t.Fatal(err)
	}
	c, err := inv.find(alice.ID)
	if err != nil || c.RevokedAt == nil || !inv.crlCurrent(time.Now()) {
		t.Fatalf("rollback unrevoked: %v", err)
	}
	m.OpenVPNPath = filepath.Join(t.TempDir(), "missing-binary")
	result, err = m.RevokeOpenVPNClient(context.Background(), bob.ID)
	if err == nil || !strings.Contains(err.Error(), "revoked, runtime not confirmed") || !result.Revoked || result.Applied {
		t.Fatalf("restart failure lost durable result: %+v %v", result, err)
	}
	inv, err = readOpenVPNInventory(filepath.Dir(invPath))
	if err != nil {
		t.Fatal(err)
	}
	c, err = inv.find(bob.ID)
	if err != nil || c.RevokedAt == nil || !inv.crlCurrent(time.Now()) {
		t.Fatalf("runtime failure rolled back revocation: %v", err)
	}
}

func TestOpenVPNCRLRenewsWhileRunning(t *testing.T) {
	m, starts := openVPNFakeManager(t)
	m.crlCheckInterval = 10 * time.Millisecond
	cfg := openVPNServerConfig()
	openVPNApply(t, m, cfg)
	openVPNAuthorityMu.Lock()
	inv, err := readOpenVPNInventory(filepath.Join(openVPNManagedServerDir(), "pki"))
	if err != nil {
		openVPNAuthorityMu.Unlock()
		t.Fatal(err)
	}
	// Persist an otherwise valid signed CRL that will expire within the renewal
	// window. The live scheduler must renew and restart via the same digest path.
	past := time.Now().Add(-openVPNCRLLifetime + openVPNCRLRenewBefore - time.Hour)
	inv.CRL = nil
	if err := inv.ensureCRL(past); err != nil {
		openVPNAuthorityMu.Unlock()
		t.Fatal(err)
	}
	oldNumber := inv.CRLNumber
	openVPNAuthorityMu.Unlock()
	waitFor(t, 3*time.Second, func() bool {
		openVPNAuthorityMu.Lock()
		defer openVPNAuthorityMu.Unlock()
		current, err := readOpenVPNInventory(inv.dir)
		return err == nil && current.CRLNumber > oldNumber && current.crlCurrent(time.Now())
	})
	waitFor(t, 3*time.Second, func() bool { b, _ := os.ReadFile(starts); return len(strings.Fields(string(b))) == 2 })
	// Drain one more scheduler cycle: current CRLs do not disconnect clients.
	m.applyMu.Lock()
	err = m.applyVPNLocked(context.Background(), cfg)
	m.applyMu.Unlock()
	if err != nil || openVPNStarts(t, starts) != 2 {
		t.Fatalf("renewal no-op restarted: %v", err)
	}
}

func TestOpenVPNStartupFailureCancellationAndReapply(t *testing.T) {
	m, _ := openVPNFakeManager(t)
	good := m.OpenVPNPath
	bad := filepath.Join(t.TempDir(), "early-exit")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	m.OpenVPNPath = bad
	cfg := openVPNServerConfig()
	if err := m.Apply(context.Background(), cfg); err == nil {
		t.Fatal("early exit reported ready")
	}
	m.OpenVPNPath = good
	openVPNApply(t, m, cfg)
	// Change config and cancel while the replacement daemon has not become ready.
	hanging := filepath.Join(t.TempDir(), "not-ready")
	if err := os.WriteFile(hanging, []byte("#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile true; do sleep 0.02; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	m.OpenVPNPath = hanging
	cfg.OpenVPN.Server.ListenPort = 1195
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := m.Apply(ctx, cfg); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("startup cancellation ignored: %v", err)
	}
	if m.Status()["openvpn_running"].(bool) {
		t.Fatal("canceled startup leaked daemon")
	}
	m.OpenVPNPath = good
	openVPNApply(t, m, cfg)
}

func TestOpenVPNCRLRenewsAfterReopen(t *testing.T) {
	m, starts := openVPNFakeManager(t)
	cfg := openVPNServerConfig()
	openVPNApply(t, m, cfg)
	alice, err := m.CreateOpenVPNClient(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.RevokeOpenVPNClient(context.Background(), alice.ID)
	if err != nil || !result.Applied {
		t.Fatalf("revoke: %v", err)
	}
	if err := m.stopOpenVPN(); err != nil {
		t.Fatal(err)
	}
	openVPNAuthorityMu.Lock()
	inv, err := readOpenVPNInventory(filepath.Join(openVPNManagedServerDir(), "pki"))
	if err != nil {
		openVPNAuthorityMu.Unlock()
		t.Fatal(err)
	}
	inv.CRL = nil
	err = inv.ensureCRL(time.Now().Add(-2 * openVPNCRLLifetime))
	oldNumber := inv.CRLNumber
	openVPNAuthorityMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	reopened := NewVPNManager(m.BaseDir)
	reopened.OpenVPNPath = m.OpenVPNPath
	reopened.SuperviseOpenVPN = true
	reopened.log = zap.NewNop().Sugar()
	t.Cleanup(func() { _ = reopened.stopOpenVPN() })
	openVPNApply(t, reopened, cfg)
	inv, err = readOpenVPNInventory(inv.dir)
	if err != nil || inv.CRLNumber <= oldNumber || !inv.crlCurrent(time.Now()) || inv.Credentials[0].RevokedAt == nil || openVPNStarts(t, starts) != 3 {
		t.Fatalf("reopen lost renewal/revocation: %v", err)
	}
	if _, err := reopened.DownloadOpenVPNClient(context.Background(), alice.ID); err == nil {
		t.Fatal("reboot unrevoked credential")
	}
}
