// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestStageDaemonFilePreservesExtension(t *testing.T) {
	for _, name := range []string{"envoy-forward.yaml", "nginx-reverse.conf", "unbound.conf", "chrony.conf", "clamd.conf", "freshclam.conf", "extensionless"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			active := filepath.Join(dir, name)
			daemonWrite(t, active, "current")
			staged, err := stageDaemonFile(active, []byte("candidate"), 0o600)
			if err != nil {
				t.Fatal(err)
			}
			ext := filepath.Ext(name)
			prefix := "." + strings.TrimSuffix(name, ext) + "-"
			base := filepath.Base(staged)
			if filepath.Dir(staged) != dir || !strings.HasPrefix(base, prefix) || !strings.HasSuffix(base, ext) ||
				len(base) <= len(prefix)+len(ext) {
				t.Fatalf("staged name %q does not preserve sibling pattern %s*%s", staged, prefix, ext)
			}
			daemonUnchanged(t, active, "current")
			daemonUnchanged(t, staged, "candidate")
			info, err := os.Stat(staged)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("staged permissions = %v", info.Mode().Perm())
			}
		})
	}
}

func TestProxyEnvoyStagedPreflight(t *testing.T) {
	binary, err := exec.LookPath("envoy")
	if err != nil {
		t.Skip("envoy binary not installed; staged parser integration requires Envoy")
	}
	m := NewProxyManager(ProxyOptions{BaseDir: t.TempDir(), EnvoyPath: binary, NginxPath: "/nonexistent/nginx"})
	cfg := config.ProxyConfig{Forward: config.ForwardProxyConfig{
		Enabled: true, ListenPort: 3128, AllowedDomains: []string{"*.vendor.example"},
	}}
	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("real Envoy staged preflight: %v", err)
	}
	path := filepath.Join(m.BaseDir, "envoy-forward.yaml")
	body, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(body), "static_resources:") {
		t.Fatalf("published YAML missing: %q, %v", body, err)
	}
	if err := m.Validate(context.Background(), cfg); err != nil {
		t.Fatalf("real Envoy disposable preflight: %v", err)
	}
	daemonUnchanged(t, path, string(body))
}
