// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package dhcpd

import (
	"context"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestUnsupportedPlatformManager(t *testing.T) {
	t.Parallel()

	mgr := NewManager()
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}

	called := false
	mgr.SetOnEvent(func(kind string, attrs map[string]any) {
		called = true
	})
	if mgr.OnEvent == nil {
		t.Fatal("SetOnEvent did not install callback")
	}

	err := mgr.Apply(context.Background(), config.DHCPConfig{}, []config.Interface{{Name: "lan1"}})
	if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("Apply error = %v, want unsupported-platform error", err)
	}
	if called {
		t.Fatal("unexpected dhcp event callback invocation on unsupported platform")
	}

	if leases := mgr.Leases(); leases != nil {
		t.Fatalf("Leases = %#v, want nil", leases)
	}
	status := mgr.Status()
	if enabled, ok := status["enabled"].(bool); !ok || enabled {
		t.Fatalf("Status enabled = %#v, want false", status["enabled"])
	}
	if note, ok := status["note"].(string); !ok || !strings.Contains(note, "not supported") {
		t.Fatalf("Status note = %#v, want unsupported-platform message", status["note"])
	}
}
