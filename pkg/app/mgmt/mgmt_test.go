// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"testing"

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
