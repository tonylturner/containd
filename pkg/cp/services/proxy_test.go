// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
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
	rendered, err := os.ReadFile(filepath.Join(dir, "envoy-forward.yaml"))
	if err != nil {
		t.Fatalf("read envoy-forward.yaml: %v", err)
	}
	if got := strings.Count(string(rendered), "dns_lookup_family: V4_ONLY"); got != 2 {
		t.Fatalf("expected dns_lookup_family in both dynamic forward proxy cache stanzas, got %d", got)
	}
	if !strings.Contains(string(rendered), "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router") {
		t.Fatal("expected forward proxy config to render a typed router filter")
	}
	reverseRendered, err := os.ReadFile(filepath.Join(dir, "nginx-reverse.conf"))
	if err != nil {
		t.Fatalf("read nginx-reverse.conf: %v", err)
	}
	if !strings.Contains(string(reverseRendered), "client_body_temp_path "+filepath.Join(dir, "nginx-tmp", "body")+";") {
		t.Fatal("expected reverse proxy config to keep nginx temp paths under the writable services dir")
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
