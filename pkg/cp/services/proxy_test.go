package services

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/containd/containd/pkg/cp/config"
)

func TestProxyManagerRendersForwardAndReverse(t *testing.T) {
	dir := t.TempDir()
	m := NewProxyManager(ProxyOptions{BaseDir: dir})

	cfg := config.ProxyConfig{
		Forward: config.ForwardProxyConfig{
			Enabled:    true,
			ListenPort: 3129,
		},
		Reverse: config.ReverseProxyConfig{
			Enabled: true,
			Sites: []config.ReverseProxySite{
				{
					Name:       "test",
					ListenPort: 8081,
					Backends:   []string{"10.0.0.10:80", "10.0.0.11:80"},
					Hostnames:  []string{"app.local"},
				},
			},
		},
	}

	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "envoy-forward.yaml")); err != nil {
		t.Fatalf("expected envoy-forward.yaml to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "nginx-reverse.conf")); err != nil {
		t.Fatalf("expected nginx-reverse.conf to exist: %v", err)
	}
}

func TestProxyManagerRemovesConfigsWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	m := NewProxyManager(ProxyOptions{BaseDir: dir})
	_ = os.WriteFile(filepath.Join(dir, "envoy-forward.yaml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "nginx-reverse.conf"), []byte("x"), 0o644)

	cfg := config.ProxyConfig{
		Forward: config.ForwardProxyConfig{Enabled: false},
		Reverse: config.ReverseProxyConfig{Enabled: false},
	}
	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "envoy-forward.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected envoy-forward.yaml removed, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "nginx-reverse.conf")); !os.IsNotExist(err) {
		t.Fatalf("expected nginx-reverse.conf removed, got %v", err)
	}
}
