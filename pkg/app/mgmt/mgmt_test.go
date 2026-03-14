// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func TestLocalEngineURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want string
		ok   bool
	}{
		{name: "default port", addr: ":8081", want: "http://127.0.0.1:8081", ok: true},
		{name: "bare port", addr: "8081", want: "http://127.0.0.1:8081", ok: true},
		{name: "ipv4 any", addr: "0.0.0.0:8081", want: "http://127.0.0.1:8081", ok: true},
		{name: "ipv6 any", addr: "[::]:8081", want: "http://127.0.0.1:8081", ok: true},
		{name: "ipv4 loopback", addr: "127.0.0.1:8081", want: "http://127.0.0.1:8081", ok: true},
		{name: "ipv6 loopback", addr: "[::1]:8081", want: "http://[::1]:8081", ok: true},
		{name: "empty", addr: "", want: "", ok: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := localEngineURL(tt.addr)
			if ok != tt.ok {
				t.Fatalf("localEngineURL(%q) ok=%v, want %v", tt.addr, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("localEngineURL(%q)=%q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestResolveEngineURL(t *testing.T) {
	logger := zap.NewNop().Sugar()

	t.Run("uses explicit env and normalizes scheme", func(t *testing.T) {
		t.Setenv("CONTAIND_ENGINE_URL", "127.0.0.1:8081")
		got := resolveEngineURL(logger, Options{})
		if got != "http://127.0.0.1:8081" {
			t.Fatalf("resolveEngineURL explicit env=%q, want %q", got, "http://127.0.0.1:8081")
		}
	})

	t.Run("derives loopback url in combined mode", func(t *testing.T) {
		t.Setenv("CONTAIND_ENGINE_URL", "")
		t.Setenv("CONTAIND_ENGINE_ADDR", ":8081")
		got := resolveEngineURL(logger, Options{Combined: true})
		if got != "http://127.0.0.1:8081" {
			t.Fatalf("resolveEngineURL combined=%q, want %q", got, "http://127.0.0.1:8081")
		}
	})

	t.Run("leaves mgmt only unset when env missing", func(t *testing.T) {
		t.Setenv("CONTAIND_ENGINE_URL", "")
		t.Setenv("CONTAIND_ENGINE_ADDR", ":8081")
		got := resolveEngineURL(logger, Options{})
		if got != "" {
			t.Fatalf("resolveEngineURL mgmt-only=%q, want empty", got)
		}
	})
}

func TestValidateJWTSecret(t *testing.T) {
	logger := zap.NewNop().Sugar()

	t.Run("rejects empty secret outside lab mode", func(t *testing.T) {
		t.Setenv("CONTAIND_JWT_SECRET", "")
		t.Setenv("CONTAIND_LAB_MODE", "0")
		if err := validateJWTSecret(logger); err == nil {
			t.Fatal("expected error for empty jwt secret outside lab mode")
		}
	})

	t.Run("allows empty secret in lab mode", func(t *testing.T) {
		t.Setenv("CONTAIND_JWT_SECRET", "")
		t.Setenv("CONTAIND_LAB_MODE", "1")
		if err := validateJWTSecret(logger); err != nil {
			t.Fatalf("validateJWTSecret error: %v", err)
		}
	})

	t.Run("rejects example secret outside lab mode", func(t *testing.T) {
		t.Setenv("CONTAIND_JWT_SECRET", "containd-dev-secret-change-me")
		t.Setenv("CONTAIND_LAB_MODE", "0")
		if err := validateJWTSecret(logger); err == nil {
			t.Fatal("expected error for example jwt secret outside lab mode")
		}
	})
}

func TestResolveMgmtListenerConfigAndBuildServers(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.ListenAddr = "10.10.10.10:8080"
	cfg.System.Mgmt.HTTPListenAddr = "10.10.10.10:8080"
	cfg.System.Mgmt.HTTPSListenAddr = "10.10.10.10:8443"
	cfg.System.Mgmt.EnableHTTP = boolPtr(true)
	cfg.System.Mgmt.EnableHTTPS = boolPtr(false)
	cfg.System.Mgmt.RedirectHTTPToHTTPS = boolPtr(true)
	cfg.System.Mgmt.EnableHSTS = boolPtr(false)
	cfg.System.Mgmt.HSTSMaxAgeSeconds = -1

	t.Setenv("CONTAIND_ALLOWED_ORIGINS", "https://ui.example")
	listenerCfg, err := resolveMgmtListenerConfig(logger, cfg)
	if err != nil {
		t.Fatalf("resolveMgmtListenerConfig: %v", err)
	}
	if listenerCfg.httpAddr != "10.10.10.10:8080" {
		t.Fatalf("httpAddr = %q", listenerCfg.httpAddr)
	}
	if listenerCfg.httpLoopbackAddr != "127.0.0.1:8080" {
		t.Fatalf("httpLoopbackAddr = %q", listenerCfg.httpLoopbackAddr)
	}
	if listenerCfg.enableHTTPS {
		t.Fatal("expected https disabled")
	}
	if listenerCfg.hstsMaxAge != 31536000 {
		t.Fatalf("hstsMaxAge = %d, want default 31536000", listenerCfg.hstsMaxAge)
	}
	if len(listenerCfg.allowedOrigins) != 1 || listenerCfg.allowedOrigins[0] != "https://ui.example" {
		t.Fatalf("allowedOrigins = %#v", listenerCfg.allowedOrigins)
	}

	listenerCfg.httpAddr = ":0"
	listenerCfg.httpLoopbackAddr = "127.0.0.1:0"
	servers, listeners, err := buildMgmtServers(http.NewServeMux(), listenerCfg)
	if err != nil {
		t.Fatalf("buildMgmtServers: %v", err)
	}
	if len(servers) != 2 || len(listeners) != 2 {
		t.Fatalf("server/listener count = %d/%d, want 2/2", len(servers), len(listeners))
	}
	for _, ln := range listeners {
		_ = ln.Close()
	}
}

func TestBuildMgmtServersRejectsNoListeners(t *testing.T) {
	_, _, err := buildMgmtServers(http.NewServeMux(), mgmtListenerConfig{})
	if err == nil {
		t.Fatal("expected no management listeners enabled error")
	}
}

func TestEnsureDefaultConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ensureDefaultConfig(logger, store)
	cfg, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if cfg.System.Hostname != "containd" {
		t.Fatalf("hostname = %q", cfg.System.Hostname)
	}
	if cfg.System.Mgmt.HTTPListenAddr != ":8080" || cfg.System.Mgmt.HTTPSListenAddr != ":8443" {
		t.Fatalf("unexpected mgmt listen addrs: http=%q https=%q", cfg.System.Mgmt.HTTPListenAddr, cfg.System.Mgmt.HTTPSListenAddr)
	}
	if !boolDefault(cfg.System.Mgmt.EnableHTTP, false) || !boolDefault(cfg.System.Mgmt.EnableHTTPS, false) {
		t.Fatal("expected default http/https listeners enabled")
	}
}
