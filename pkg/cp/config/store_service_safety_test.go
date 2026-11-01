// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestStoreServiceSafetyRejectsUnsafeCandidate(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	safe := DefaultConfig()
	safe.System.Hostname = "safe-candidate"
	if err := store.SaveCandidate(ctx, safe); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Services.DNS.UpstreamServers = []string{"1.1.1.1\nserver:"} },
		func(c *Config) { c.Services.Proxy.Forward.AllowedClients = []string{"old-client"} },
		func(c *Config) {
			c.Services.Proxy.Reverse.Sites = []ReverseProxySite{{
				Name: "app", ListenPort: 443, TLSEnabled: true, Backends: []string{"127.0.0.1:80"},
			}}
		},
		func(c *Config) {
			c.Services.VPN.OpenVPN.Server = &OpenVPNManagedServerConfig{PublicEndpoint: "vpn.example\nup injected"}
		},
	} {
		unsafe := DefaultConfig()
		unsafe.System.Hostname = "unsafe-candidate"
		mutate(unsafe)
		var fault *ServiceConfigError
		if err := store.SaveCandidate(ctx, unsafe); !errors.As(err, &fault) {
			t.Fatalf("store accepted unsafe config or lost service type: %v", err)
		}
		candidate, err := store.LoadCandidate(ctx)
		if err != nil || candidate.System.Hostname != "safe-candidate" {
			t.Fatalf("rejected write changed candidate: cfg=%+v err=%v", candidate, err)
		}
	}
}
