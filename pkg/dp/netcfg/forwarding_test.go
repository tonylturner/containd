// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package netcfg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestReadIPv4ForwardingStatus(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ip_forward")
	for _, tc := range []struct {
		name string
		data string
		want IPv4ForwardingStatus
	}{
		{name: "enabled", data: "1\n", want: IPv4ForwardingEnabled},
		{name: "disabled", data: "0\n", want: IPv4ForwardingDisabled},
		{name: "unrecognized", data: "2\n", want: IPv4ForwardingUnknown},
		{name: "empty", data: "", want: IPv4ForwardingUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := readIPv4ForwardingStatus(path); got != tc.want {
				t.Fatalf("readIPv4ForwardingStatus() = %q, want %q", got, tc.want)
			}
		})
	}

	if got := readIPv4ForwardingStatus(filepath.Join(t.TempDir(), "missing")); got != IPv4ForwardingUnknown {
		t.Fatalf("missing sysctl status = %q, want %q", got, IPv4ForwardingUnknown)
	}
}

func TestRequiresIPv4Forwarding(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		ifaces []config.Interface
		want   bool
	}{
		{
			name:   "two zone devices",
			ifaces: []config.Interface{{Name: "wan", Zone: "wan"}, {Name: "lan", Zone: "lan"}},
			want:   true,
		},
		{
			name:   "same device",
			ifaces: []config.Interface{{Name: "wan", Device: "eth0", Zone: "wan"}, {Name: "lan", Device: "eth0", Zone: "lan"}},
		},
		{
			name:   "unassigned zone",
			ifaces: []config.Interface{{Name: "wan", Zone: "wan"}, {Name: "lan"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RequiresIPv4Forwarding(tc.ifaces); got != tc.want {
				t.Fatalf("RequiresIPv4Forwarding() = %t, want %t", got, tc.want)
			}
		})
	}
}
