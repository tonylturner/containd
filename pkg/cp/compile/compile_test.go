package compile

import (
	"testing"

	"github.com/containd/containd/pkg/cp/config"
	"github.com/containd/containd/pkg/dp/rules"
)

func TestCompileSnapshotFirewallMapping(t *testing.T) {
	cfg := &config.Config{
		System: config.SystemConfig{Hostname: "containd"},
		Zones:  []config.Zone{{Name: "it"}},
		Firewall: config.FirewallConfig{
			DefaultAction: config.ActionDeny,
			Rules: []config.Rule{
				{
					ID:          "1",
					SourceZones: []string{"it"},
					Protocols:   []config.Protocol{{Name: "tcp", Port: "502"}},
					ICS: config.ICSPredicate{
						Protocol:     "modbus",
						FunctionCode: []uint8{3, 16},
						Addresses:    []string{"0-100"},
					},
					Action: config.ActionAllow,
				},
			},
		},
	}
	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if snap.Default != rules.ActionDeny {
		t.Fatalf("expected default deny, got %s", snap.Default)
	}
	if len(snap.Firewall) != 1 || snap.Firewall[0].ID != "1" {
		t.Fatalf("unexpected firewall entries: %+v", snap.Firewall)
	}
	if snap.Firewall[0].ICS.Protocol != "modbus" || len(snap.Firewall[0].ICS.FunctionCode) != 2 {
		t.Fatalf("expected ics predicate to be compiled, got %+v", snap.Firewall[0].ICS)
	}
	if snap.Firewall[0].Action != rules.ActionAllow {
		t.Fatalf("expected allow action, got %s", snap.Firewall[0].Action)
	}
}

func TestCompileSnapshotPortForwards(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Zones = []config.Zone{{Name: "wan"}, {Name: "lan"}}
	cfg.Interfaces = []config.Interface{
		{Name: "wan", Zone: "wan", Device: "eth0"},
		{Name: "lan1", Zone: "lan", Device: "eth1"},
	}
	cfg.Firewall.NAT.PortForwards = []config.PortForward{
		{
			ID:          "pf-ssh",
			Enabled:     true,
			IngressZone: "wan",
			Proto:       "tcp",
			ListenPort:  2222,
			DestIP:      "192.168.242.10",
			DestPort:    22,
		},
	}

	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(snap.NAT.PortForwards) != 1 {
		t.Fatalf("expected 1 port forward, got %d", len(snap.NAT.PortForwards))
	}
	pf := snap.NAT.PortForwards[0]
	if pf.ID != "pf-ssh" || pf.DestPort != 22 || pf.ListenPort != 2222 || pf.IngressZone != "wan" || pf.Proto != "tcp" {
		t.Fatalf("unexpected port forward: %+v", pf)
	}
}

func TestExpandCIDRTokensVPN(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Zones = []config.Zone{{Name: "wan"}, {Name: "lan"}}
	cfg.Interfaces = []config.Interface{
		{Name: "wan", Zone: "wan", Device: "eth0"},
		{Name: "lan1", Zone: "lan", Device: "eth1"},
	}

	cfg.Services.VPN.WireGuard.Enabled = true
	cfg.Services.VPN.WireGuard.AddressCIDR = "10.8.0.1/24"
	cfg.Services.VPN.OpenVPN.Enabled = true
	cfg.Services.VPN.OpenVPN.Mode = "server"
	cfg.Services.VPN.OpenVPN.Server = &config.OpenVPNManagedServerConfig{
		ListenPort:  1194,
		Proto:       "udp",
		TunnelCIDR:  "10.9.0.0/24",
		PublicEndpoint: "vpn.example.com",
	}

	cfg.Firewall.Rules = []config.Rule{
		{
			ID:          "vpn-any",
			SourceZones: []string{"lan"},
			DestZones:   []string{"wan"},
			Sources:     []string{"vpn:any"},
			Action:      config.ActionAllow,
			Protocols:   []config.Protocol{{Name: "tcp", Port: "443"}},
		},
		{
			ID:          "vpn-wg",
			SourceZones: []string{"lan"},
			DestZones:   []string{"wan"},
			Sources:     []string{"vpn:wireguard"},
			Action:      config.ActionAllow,
			Protocols:   []config.Protocol{{Name: "tcp", Port: "443"}},
		},
		{
			ID:          "vpn-ovpn",
			SourceZones: []string{"lan"},
			DestZones:   []string{"wan"},
			Sources:     []string{"vpn:openvpn"},
			Action:      config.ActionAllow,
			Protocols:   []config.Protocol{{Name: "tcp", Port: "443"}},
		},
	}

	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(snap.Firewall) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(snap.Firewall))
	}
	if got := snap.Firewall[0].Sources; len(got) != 2 || got[0] != "10.8.0.1/24" || got[1] != "10.9.0.0/24" {
		t.Fatalf("vpn:any expansion unexpected: %+v", got)
	}
	if got := snap.Firewall[1].Sources; len(got) != 1 || got[0] != "10.8.0.1/24" {
		t.Fatalf("vpn:wireguard expansion unexpected: %+v", got)
	}
	if got := snap.Firewall[2].Sources; len(got) != 1 || got[0] != "10.9.0.0/24" {
		t.Fatalf("vpn:openvpn expansion unexpected: %+v", got)
	}
}
