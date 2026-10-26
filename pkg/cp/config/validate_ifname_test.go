// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestKernelInterfaceNames: a device binding, and the name of an interface
// without one, must be a name Linux accepts for a device that nft can
// match exactly; so must a DHCP listen interface that names a device.
func TestKernelInterfaceNames(t *testing.T) {
	valid := []string{"eth0", "enp0s31f6", "br-lan.10", "abcdefghijklmno"}
	invalid := []string{"abcdefghijklmnop", "eth/0", "eth:0", `eth"0`, "eth*", `eth\0`, ".", "..", "eth\x01"}
	for _, tc := range []struct {
		name  string
		set   func(c *Config, v string)
		field string
	}{
		{"device", func(c *Config, v string) { c.Interfaces[0].Device = v }, "device"},
		{"name without device", func(c *Config, v string) {
			c.Interfaces = append(c.Interfaces, Interface{Name: v, Zone: "lan"})
		}, "kernel name"},
		{"dhcp listen interface", func(c *Config, v string) {
			c.Services.DHCP.Enabled = true
			c.Services.DHCP.ListenIfaces = []string{"lan2", v}
		}, "dhcp listenIfaces"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range valid {
				cfg := DefaultConfig()
				tc.set(cfg, v)
				if err := cfg.Validate(); err != nil {
					t.Errorf("%q refused: %v", v, err)
				}
			}
			for _, v := range invalid {
				cfg := DefaultConfig()
				tc.set(cfg, v)
				if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "invalid interface name") {
					t.Errorf("%q: %v", v, err)
				}
			}
		})
	}
	cfg := DefaultConfig()
	cfg.Interfaces = append(cfg.Interfaces, Interface{Name: "Plant Floor", Device: "eth9", Zone: "lan"})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a bound interface's name is free text: %v", err)
	}
}
