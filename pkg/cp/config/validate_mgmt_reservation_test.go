// SPDX-License-Identifier: Apache-2.0
package config

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
)

func reservationFixture() (*Config, *mgmtpath.Reservation) {
	r := &mgmtpath.Reservation{Device: "eth7", Local: netip.MustParsePrefix("10.99.99.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10"), netip.MustParseAddr("10.99.99.3")}, Port: 8080}
	c := DefaultConfig()
	c.Interfaces = []Interface{{Name: "lan3", Device: "eth7", Zone: "lan"}, {Name: "wan", Device: "eth0", Zone: "wan"}}
	c.DataPlane.Enforcement = true
	return c, r
}
func TestManagementReservationRejections(t *testing.T) {
	f := false
	tr := true
	tests := []struct {
		name, field string
		edit        func(*Config)
	}{
		{"http disabled", "enableHTTP", func(c *Config) { c.System.Mgmt.EnableHTTP = &f }},
		{"redirect", "redirect", func(c *Config) { c.System.Mgmt.RedirectHTTPToHTTPS = &tr }},
		{"http port", "httpListenAddr", func(c *Config) { c.System.Mgmt.HTTPListenAddr = ":9090" }},
		{"legacy alias", "listenAddr", func(c *Config) { c.System.Mgmt.ListenAddr = ":9090" }},
		{"https collision", "httpsListenAddr", func(c *Config) { c.System.Mgmt.HTTPSListenAddr = ":8080" }},
		{"ssh collision", "ssh", func(c *Config) { c.System.SSH.ListenAddr = "10.99.99.2:8080" }},
		{"enforcement off", "enforcement", func(c *Config) { c.DataPlane.Enforcement = false }},
		{"reserved static", "addresses", func(c *Config) { c.Interfaces[0].Addresses = []string{"192.0.2.2/24"} }},
		{"reserved DHCP", "addressMode", func(c *Config) { c.Interfaces[0].AddressMode = "dhcp" }},
		{"move binding", "interfaces.device", func(c *Config) { c.Interfaces[0].Device = "eth8" }},
		{"duplicate binding", "interfaces.device", func(c *Config) { c.Interfaces = append(c.Interfaces, Interface{Name: "another", Device: "eth7"}) }},
		{"virtual binding", "type", func(c *Config) { c.Interfaces[0].Type = "bridge" }},
		{"bridge member", "members", func(c *Config) {
			c.Interfaces = append(c.Interfaces, Interface{Name: "br0", Type: "bridge", Members: []string{"lan3"}})
		}},
		{"vlan parent", "parent", func(c *Config) { c.Interfaces = append(c.Interfaces, Interface{Name: "vlan0", Parent: "lan3"}) }},
		{"local elsewhere", "addresses", func(c *Config) { c.Interfaces[1].Addresses = []string{"10.99.99.2/32"} }},
		{"source takeover", "addresses", func(c *Config) { c.Interfaces[1].Addresses = []string{"10.99.99.10/32"} }},
		{"mapped source alias", "addresses", func(c *Config) { c.Interfaces[1].Addresses = []string{"::ffff:10.99.99.10/128"} }},
		{"WG disabled deletion", "wireguard.interface", func(c *Config) { c.Services.VPN.WireGuard.Interface = "eth7" }},
		{"WG address covers local", "addressCIDR", func(c *Config) { c.Services.VPN.WireGuard.AddressCIDR = "10.99.99.1/24" }},
		{"WG source takeover", "addressCIDR", func(c *Config) { c.Services.VPN.WireGuard.AddressCIDR = "10.99.99.3/32" }},
		{"VPN tunnel covers local", "tunnelCIDR", func(c *Config) {
			c.Services.VPN.OpenVPN.Server = &OpenVPNManagedServerConfig{TunnelCIDR: "10.99.99.0/24"}
		}},
		{"VPN computed source", "tunnelCIDR", func(c *Config) {
			c.Services.VPN.OpenVPN.Server = &OpenVPNManagedServerConfig{TunnelCIDR: "10.99.99.2/31"}
		}},
		{"DHCP pool", "dhcp.pools", func(c *Config) {
			c.Services.DHCP = DHCPConfig{Enabled: true, Pools: []DHCPPool{{Start: "10.99.99.9", End: "10.99.99.11"}}}
		}},
		{"DHCP reservation", "dhcp.reservations", func(c *Config) {
			c.Services.DHCP = DHCPConfig{Enabled: true, Reservations: []DHCPReservation{{IP: "10.99.99.3"}}}
		}},
		{"forward proxy", "proxy.forward", func(c *Config) { c.Services.Proxy.Forward = ForwardProxyConfig{Enabled: true, ListenPort: 8080} }},
		{"reverse proxy", "proxy.reverse", func(c *Config) {
			c.Services.Proxy.Reverse = ReverseProxyConfig{Enabled: true, Sites: []ReverseProxySite{{ListenPort: 8080}}}
		}},
		{"DNS TCP listener", "dns.listenPort", func(c *Config) { c.Services.DNS = DNSConfig{Enabled: true, ListenPort: 8080} }},
		{"DNAT global toggle irrelevant", "portForwards", func(c *Config) {
			c.Firewall.NAT.PortForwards = []PortForward{{Enabled: true, Proto: "tcp", ListenPort: 8080, IngressZone: "lan"}}
		}},
		{"priority1 wildcard", "routing.rules", func(c *Config) { c.Routing.Rules = []PolicyRule{{Priority: 1, Table: 201}} }},
		{"priority wrap to kernel zero", "routing.rules", func(c *Config) { c.Routing.Rules = []PolicyRule{{Priority: 1 << 32, Table: 201}} }},
		{"local table default via partial API", "routing.routes", func(c *Config) { c.Routing.Routes = []StaticRoute{{Dst: "0.0.0.0/0", Table: 255, Iface: "wan"}} }},
		{"priority1 exact", "routing.rules", func(c *Config) {
			c.Routing.Rules = []PolicyRule{{Priority: 1, Src: "10.99.99.2/32", Dst: "10.99.99.10/32", Table: 201}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, r := reservationFixture()
			tc.edit(c)
			err := ValidateManagementReservation(c, r)
			if err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "reserved management path") {
				t.Fatalf("got %v, want %s reservation rejection", err, tc.field)
			}
		})
	}
}
func TestManagementReservationAllowed(t *testing.T) {
	for _, edit := range []func(*Config){func(c *Config) {
		f := false
		for i := range c.Interfaces {
			c.Interfaces[i].Access = InterfaceAccess{Mgmt: &f, HTTP: &f, HTTPS: &f, SSH: &f}
		}
	}, func(c *Config) { c.Interfaces[0].Name = "renamed"; c.Interfaces[0].Zone = "wan" }, func(c *Config) {
		c.Interfaces[0].Gateway = "192.0.2.1" // A route hint, not an assigned local address.
	}, func(c *Config) {
		c.Routing = RoutingConfig{Routes: []StaticRoute{{Dst: "10.99.99.10/32", Iface: "wan"}}, Rules: []PolicyRule{{Priority: 0, Table: 201}, {Priority: 2, Table: 201}, {Priority: 9000, Table: 201}, {Priority: 10000, Table: 201}, {Priority: 1, Src: "192.0.2.0/24", Table: 201}}}
	}, func(c *Config) {
		c.Services.VPN.OpenVPN = OpenVPNConfig{Enabled: true, ConfigPath: "/not/read/by/pure/validator"}
	}, func(c *Config) { c.Services.VPN.WireGuard.Peers = []WGPeer{{AllowedIPs: []string{"0.0.0.0/0"}}} }, func(c *Config) {
		c.Firewall.NAT.PortForwards = []PortForward{{Enabled: true, Proto: "tcp", ListenPort: 8080, IngressZone: "lan", AllowedSources: []string{"192.0.2.0/24"}}}
	}} {
		c, r := reservationFixture()
		edit(c)
		if err := ValidateManagementReservation(c, r); err != nil {
			t.Error(err)
		}
	}
	if err := ValidateManagementReservation(nil, nil); err != nil {
		t.Fatal(err)
	}
}
