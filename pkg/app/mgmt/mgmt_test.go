// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		t.Setenv("CONTAIND_ENGINE_ADDR", "")
		t.Setenv("NGFW_ENGINE_ADDR", "")
		got := resolveEngineURL(logger, Options{Combined: true})
		if got != "http://127.0.0.1:8081" {
			t.Fatalf("resolveEngineURL combined=%q, want %q", got, "http://127.0.0.1:8081")
		}
	})

	t.Run("derives explicit combined listener", func(t *testing.T) {
		t.Setenv("CONTAIND_ENGINE_URL", "")
		t.Setenv("CONTAIND_ENGINE_ADDR", "127.0.0.1:9091")
		if got := resolveEngineURL(logger, Options{Combined: true}); got != "http://127.0.0.1:9091" {
			t.Fatalf("resolveEngineURL override = %q", got)
		}
	})

	t.Run("preserves explicit combined URL", func(t *testing.T) {
		t.Setenv("CONTAIND_ENGINE_URL", "http://127.0.0.1:8081")
		t.Setenv("CONTAIND_ENGINE_ADDR", "")
		if got := resolveEngineURL(logger, Options{Combined: true}); got != "http://127.0.0.1:8081" {
			t.Fatalf("resolveEngineURL explicit combined = %q", got)
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
	listenerCfg, err := resolveMgmtListenerConfig(logger, cfg, nil)
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

// A stored rule with an ICS address entry that validation now refuses starts
// management in recovery, with the rule and the entry in the boot fault,
// and leaves the stored rule for the operator to fix.
func TestStoredBadICSAddressBootsIntoRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.db")
	t.Setenv("CONTAIND_CONFIG_DB", path)
	t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(dir, "audit.db"))
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(dir, "users.db"))
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Save(ctx, config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	setStoredRules(t, path, []config.Rule{{
		ID: "modbus-addr", Action: config.ActionAllow,
		Protocols: []config.Protocol{{Name: "tcp", Port: "502"}},
		ICS:       config.ICSPredicate{Protocol: "modbus", Mode: "learn", Addresses: []string{"0x0100", "0x01G0"}},
	}})

	stores, running, err := initMgmtStores(zap.NewNop().Sugar(), nil)
	if err != nil {
		t.Fatalf("a bad stored address stopped management: %v", err)
	}
	defer stores.store.Close()
	defer stores.auditStore.Close()
	defer stores.userStore.Close()
	fault, err := config.ManagementBootFaultForStore(ctx, stores.store)
	if err != nil || !strings.Contains(fault, `rule modbus-addr ics addresses entry "0x01G0"`) {
		t.Fatalf("fault = %q, %v", fault, err)
	}
	if !errors.Is(config.CheckManagementBootFault(ctx, stores.store), config.ErrManagementBootFault) {
		t.Fatal("boot is not in recovery")
	}
	if len(running.Firewall.Rules) != 1 || !slices.Equal(running.Firewall.Rules[0].ICS.Addresses, []string{"0x0100", "0x01G0"}) {
		t.Fatalf("boot rewrote the stored rules: %+v", running.Firewall.Rules)
	}
}

// The certificate recorded for the console is the one the HTTPS listener
// serves: an environment override, generated when missing, rather than the
// saved setting; none when HTTPS is not served.
func TestServedCertificateIsTheListenerCertificate(t *testing.T) {
	dir := t.TempDir()
	envCert := filepath.Join(dir, "env.crt")
	t.Setenv("CONTAIND_TLS_CERT_FILE", envCert)
	t.Setenv("CONTAIND_TLS_KEY_FILE", filepath.Join(dir, "env.key"))
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TLSCertFile = filepath.Join(dir, "saved.crt")
	cfg.System.Mgmt.TLSKeyFile = filepath.Join(dir, "saved.key")
	cfg.System.Mgmt.EnableHTTP = boolPtr(false)
	listener, err := resolveMgmtListenerConfig(zap.NewNop().Sugar(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := listener.servedCertificate(); got != envCert {
		t.Fatalf("served certificate = %q, want %q", got, envCert)
	}
	if _, err := os.Stat(envCert); err != nil {
		t.Fatalf("served certificate not generated: %v", err)
	}
	cfg.System.Mgmt.EnableHTTPS = boolPtr(false)
	cfg.System.Mgmt.EnableHTTP = boolPtr(true)
	if listener, err = resolveMgmtListenerConfig(zap.NewNop().Sugar(), cfg, nil); err != nil || listener.servedCertificate() != "" {
		t.Fatalf("served certificate without HTTPS = %q, %v", listener.servedCertificate(), err)
	}
}
