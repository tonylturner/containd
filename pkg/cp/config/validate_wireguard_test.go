// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestWireGuardAddressFamilies(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, tc := range []struct {
			name, address, allowed, endpoint, field string
		}{
			{"IPv4", "10.8.0.1/24", "10.8.0.2/32", "192.0.2.1:51820", ""},
			{"hostname", "10.8.0.1/24", "0.0.0.0/0", "vpn.example.com:51820", ""},
			{"interface IPv6", "2001:db8::1/64", "10.8.0.2/32", "", "addressCIDR"},
			{"interface mapped IPv6", "::ffff:192.0.2.1/128", "10.8.0.2/32", "", "addressCIDR"},
			{"allowed IPv6", "10.8.0.1/24", "::/0", "", "allowedIPs[0]"},
			{"allowed mapped IPv6", "10.8.0.1/24", "::ffff:192.0.2.1/128", "", "allowedIPs[0]"},
			{"endpoint IPv6", "10.8.0.1/24", "10.8.0.2/32", "[2001:db8::1]:51820", "endpoint"},
			{"endpoint scoped IPv6", "10.8.0.1/24", "10.8.0.2/32", "[fe80::1%eth0]:51820", "endpoint"},
		} {
			t.Run(tc.name+map[bool]string{false: "/disabled", true: "/enabled"}[enabled], func(t *testing.T) {
				cfg := Config{}
				cfg.Services.VPN.WireGuard = WireGuardConfig{
					Enabled: enabled, AddressCIDR: tc.address,
					Peers: []WGPeer{{PublicKey: "peer-public", AllowedIPs: []string{tc.allowed}, Endpoint: tc.endpoint}},
				}
				err := cfg.Validate()
				if tc.field == "" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "IPv4") {
					t.Fatalf("expected IPv4 error for %s, got %v", tc.field, err)
				}
			})
		}
	}
}
