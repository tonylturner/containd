// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagementListenerSyntax(t *testing.T) {
	fields := []struct {
		name string
		set  func(*Config, string)
	}{
		{"mgmt.listenAddr", func(c *Config, v string) { c.System.Mgmt.ListenAddr = v }},
		{"mgmt.httpListenAddr", func(c *Config, v string) { c.System.Mgmt.HTTPListenAddr = v }},
		{"mgmt.httpsListenAddr", func(c *Config, v string) { c.System.Mgmt.HTTPSListenAddr = v }},
		{"ssh.listenAddr", func(c *Config, v string) { c.System.SSH.ListenAddr = v }},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			for _, value := range []string{"", ":8080", "127.0.0.1:8080", "[::1]:8443", "localhost:8443", "192.0.2.250:8443"} {
				cfg := DefaultConfig()
				field.set(cfg, value)
				if err := cfg.Validate(); err != nil {
					t.Errorf("valid %q: %v", value, err)
				}
			}
			for _, value := range []string{"8443", "localhost", ":https", "http://localhost:8080", ":0", ":-1", ":+80", ":65536", "localhost:", " localhost:8080", "local host:8080", "::1:8443", "[invalid::ip]:80", "bad?host:80", "[localhost]:80"} {
				cfg := DefaultConfig()
				field.set(cfg, value)
				if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), field.name) {
					t.Errorf("invalid %q: %v", value, err)
				}
			}
		})
	}
}

func TestCommitRejectsLegacyMalformedListener(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	cfg := DefaultConfig()
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.System.Mgmt.HTTPSListenAddr = "not-host-port"
	data, err := marshalStoredConfig(configKeyCandidate, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES ('candidate',?,0)`, string(data)); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx); err == nil || !strings.Contains(err.Error(), "mgmt.httpsListenAddr") {
		t.Fatalf("commit malformed listener: %v", err)
	}
	running, err := store.Load(ctx)
	if err != nil || running.System.Mgmt.HTTPSListenAddr == "not-host-port" {
		t.Fatalf("invalid candidate promoted: %+v %v", running, err)
	}
}
