// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func TestLocalEngineURL(t *testing.T) {
	for _, tc := range []struct{ addr, want string }{
		{":8081", "https://127.0.0.1:8081"},
		{"0.0.0.0:8081", "https://127.0.0.1:8081"},
		{"[::]:8081", "https://[::1]:8081"},
		{"[0:0:0:0:0:0:0:0]:8081", "https://[::1]:8081"},
		{"[::ffff:0.0.0.0]:8081", "https://127.0.0.1:8081"},
		{"127.0.0.1:8081", "http://127.0.0.1:8081"},
		{"[::1]:8081", "http://[::1]:8081"},
		{"192.0.2.1:8081", "https://192.0.2.1:8081"},
		{"localhost:8081", "https://localhost:8081"},
	} {
		got, ok := localEngineURL(tc.addr)
		if !ok || got != tc.want {
			t.Fatalf("%s: got %s, %t", tc.addr, got, ok)
		}
	}
	if _, ok := localEngineURL(""); ok {
		t.Fatal("empty listener accepted")
	}
}

func TestResolveEngineURL(t *testing.T) {
	secret := hex.EncodeToString([]byte("public engine transport test key"))
	for _, tc := range []struct {
		name, raw, addr, legacy, secret, want string
		combined, bad                         bool
	}{
		{name: "normalize local", raw: "127.0.0.1:8081", want: "http://127.0.0.1:8081"},
		{name: "default combined", combined: true, want: "http://127.0.0.1:8081"},
		{name: "wildcard", combined: true, addr: ":8081", secret: secret, want: "https://127.0.0.1:8081"},
		{name: "v6 wildcard", combined: true, addr: "[::]:8081", secret: secret, want: "https://[::1]:8081"},
		{name: "interface", combined: true, addr: "192.0.2.1:8081", secret: secret, want: "https://192.0.2.1:8081"},
		{name: "legacy remote addr", combined: true, legacy: ":8081", secret: secret, want: "https://127.0.0.1:8081"},
		{name: "legacy local addr", combined: true, legacy: "127.0.0.1:9091", want: "http://127.0.0.1:9091"},
		{name: "localhost needs secret", combined: true, addr: "localhost:8081", bad: true},
		{name: "localhost TLS", combined: true, addr: "localhost:8081", secret: secret, want: "https://localhost:8081"},
		{name: "explicit plaintext mismatch", combined: true, addr: ":8081", secret: secret, raw: "http://127.0.0.1:8081", bad: true},
		{name: "unused invalid secret", combined: true, secret: "invalid", want: "http://127.0.0.1:8081"},
		{name: "mgmt only unset", addr: ":8081"},
		{name: "remote plaintext", raw: "http://192.0.2.1:8081", bad: true},
		{name: "remote schemeless", raw: "192.0.2.1:8081", bad: true},
		{name: "https needs secret", raw: "https://127.0.0.1:8081", bad: true},
		{name: "https with secret", raw: "https://engine:8081", secret: secret, want: "https://engine:8081"},
		{name: "credentials", raw: "http://user:pass@127.0.0.1:8081", bad: true},
		{name: "path", raw: "http://127.0.0.1:8081/", bad: true},
		{name: "query", raw: "http://127.0.0.1:8081?x", bad: true},
		{name: "fragment", raw: "http://127.0.0.1:8081#x", bad: true},
		{name: "unix", raw: "unix:///tmp/engine", bad: true},
		{name: "port", raw: "http://127.0.0.1:65536", bad: true},
		{name: "missing host", raw: "http://:8081", bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTAIND_ENGINE_URL", tc.raw)
			t.Setenv("NGFW_ENGINE_URL", "")
			t.Setenv("CONTAIND_ENGINE_ADDR", tc.addr)
			t.Setenv("NGFW_ENGINE_ADDR", tc.legacy)
			t.Setenv("CONTAIND_ENGINE_SECRET", tc.secret)
			target, err := resolveEngineURL(zap.NewNop().Sugar(), Options{Combined: tc.combined})
			if (err != nil) != tc.bad {
				t.Fatalf("target %v err %v", target, err)
			}
			if err != nil {
				if tc.name == "explicit plaintext mismatch" && (!strings.Contains(err.Error(), "CONTAIND_ENGINE_ADDR") || !strings.Contains(err.Error(), "CONTAIND_ENGINE_URL")) {
					t.Fatal(err)
				}
				return
			}
			got := ""
			if target != nil {
				got = target.URL()
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
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
	binds, err := buildMgmtServers(http.NewServeMux(), listenerCfg)
	if err != nil {
		t.Fatalf("buildMgmtServers: %v", err)
	}
	defer binds.close()
	if len(binds.servers) != 2 || len(binds.listeners) != 2 {
		t.Fatalf("server/listener count = %d/%d, want 2/2", len(binds.servers), len(binds.listeners))
	}
}

func TestBuildMgmtServersRejectsNoListeners(t *testing.T) {
	_, err := buildMgmtServers(http.NewServeMux(), mgmtListenerConfig{})
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
		ICS:       config.ICSPredicate{Protocol: "modbus", Mode: "monitor", Addresses: []string{"0x0100", "0x01G0"}},
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

// The certificate and key recorded for the console and SSH are the files the
// HTTPS listener serves: read-only environment overrides,
// rather than the saved settings; none when HTTPS is not served.
func TestServedCertificateIsTheListenerCertificate(t *testing.T) {
	dir := t.TempDir()
	envCert, envKey, _ := sshTestKeyPair(t, dir, "env")
	t.Setenv("CONTAIND_TLS_CERT_FILE", envCert)
	t.Setenv("CONTAIND_TLS_KEY_FILE", envKey)
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TLSCertFile = filepath.Join(dir, "saved.crt")
	cfg.System.Mgmt.TLSKeyFile = filepath.Join(dir, "saved.key")
	cfg.System.Mgmt.EnableHTTP = boolPtr(false)
	listener, err := resolveMgmtListenerConfig(zap.NewNop().Sugar(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := listener.servedManagement(configuredBinds(listener)); got.CertFile != envCert || got.KeyFile != envKey {
		t.Fatalf("served = %+v, want %q and %q", got, envCert, envKey)
	}
	if _, err := os.Stat(envCert); err != nil {
		t.Fatalf("served certificate missing: %v", err)
	}
	cfg.System.Mgmt.EnableHTTPS = boolPtr(false)
	cfg.System.Mgmt.EnableHTTP = boolPtr(true)
	if listener, err = resolveMgmtListenerConfig(zap.NewNop().Sugar(), cfg, nil); err != nil || listener.servedManagement(configuredBinds(listener)) != (httpapi.ServedManagement{}) {
		t.Fatalf("served without HTTPS = %+v, %v", listener.servedManagement(configuredBinds(listener)), err)
	}
}
