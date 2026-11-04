// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// Row names and literal DHCP listen selectors must be safe kernel names.
func TestKernelInterfaceNames(t *testing.T) {
	valid := []string{"eth0", "enp0s31f6", "br-lan.10", "abcdefghijklmno"}
	invalid := []string{"abcdefghijklmnop", "eth/0", "eth:0", `eth"0`, "eth*", `eth\0`, ".", "..", "eth\x01"}
	for _, tc := range []struct {
		name  string
		set   func(c *Config, v string)
		field string
	}{
		{"row name", func(c *Config, v string) {
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
	cfg.Interfaces = append(cfg.Interfaces, Interface{Name: "Plant Floor", Zone: "lan"})
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid row name accepted")
	}
}

func TestInterfaceParentsAndMembersRequireRows(t *testing.T) {
	for _, row := range []Interface{
		{Name: "vlan10", Type: "vlan", Parent: "eth99", VLANID: 10},
		{Name: "br0", Type: "bridge", Members: []string{"eth99"}},
	} {
		cfg := DefaultConfig()
		cfg.Interfaces = append(cfg.Interfaces, row)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("bare kernel reference accepted: %+v %v", row, err)
		}
	}
}
