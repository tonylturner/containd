package config

import "testing"

func TestValidateHappyPath(t *testing.T) {
	cfg := Config{
		System: SystemConfig{Hostname: "containd"},
		Zones: []Zone{
			{Name: "it"},
			{Name: "dmz"},
		},
		Interfaces: []Interface{
			{Name: "eth0", Zone: "it", Addresses: []string{"192.168.1.1/24"}},
			{Name: "eth1", Zone: "dmz", Addresses: []string{"10.0.0.1/24"}},
		},
		Firewall: FirewallConfig{
			DefaultAction: ActionDeny,
			Rules: []Rule{
				{
					ID:           "1",
					SourceZones:  []string{"it"},
					DestZones:    []string{"dmz"},
					Sources:      []string{"192.168.1.0/24"},
					Destinations: []string{"10.0.0.0/24"},
					Action:       ActionAllow,
				},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidateInterfaceGateway(t *testing.T) {
	cfg := Config{
		Zones: []Zone{{Name: "it"}},
		Interfaces: []Interface{
			{Name: "eth0", Zone: "it", Addresses: []string{"192.168.1.1/24"}, Gateway: "not-an-ip"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid gateway error")
	}
}

func TestValidateInterfaceAddressMode(t *testing.T) {
	cfg := Config{
		Zones: []Zone{{Name: "it"}},
		Interfaces: []Interface{
			{Name: "eth0", Zone: "it", AddressMode: "bogus"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid addressMode error")
	}
}

func TestValidateDetectsDuplicates(t *testing.T) {
	cfg := Config{
		Zones: []Zone{{Name: "it"}, {Name: "it"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected duplicate zone error")
	}
}

func TestValidateInterfaceZoneResolution(t *testing.T) {
	cfg := Config{
		Zones: []Zone{{Name: "it"}},
		Interfaces: []Interface{
			{Name: "eth0", Zone: "dmz"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected unknown zone error")
	}
}

func TestValidateRuleCIDR(t *testing.T) {
	cfg := Config{
		Zones: []Zone{{Name: "it"}},
		Firewall: FirewallConfig{
			Rules: []Rule{
				{
					ID:           "bad",
					SourceZones:  []string{"it"},
					Destinations: []string{"not-a-cidr"},
					Action:       ActionAllow,
				},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected CIDR validation error")
	}
}

func TestValidateAssets(t *testing.T) {
	cfg := Config{
		Zones: []Zone{{Name: "ot"}},
		Assets: []Asset{
			{ID: "a1", Name: "plc-1", Type: AssetPLC, Zone: "ot", IPs: []string{"10.0.0.10"}, Criticality: CriticalityHigh},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid assets, got %v", err)
	}
	cfg.Assets = append(cfg.Assets, Asset{ID: "a1", Name: "dup"})
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected duplicate asset id error")
	}
}

func TestValidatePortForwardOverlap(t *testing.T) {
	cfg := Config{
		Zones: []Zone{{Name: "wan"}},
		Interfaces: []Interface{
			{Name: "eth0", Zone: "wan"},
		},
		Firewall: FirewallConfig{
			DefaultAction: ActionDeny,
			NAT: NATConfig{
				PortForwards: []PortForward{
					{
						ID:             "pf-1",
						Enabled:        true,
						IngressZone:    "wan",
						Proto:          "tcp",
						ListenPort:     443,
						DestIP:         "10.0.0.10",
						AllowedSources: []string{"203.0.113.0/24"},
					},
					{
						ID:             "pf-2",
						Enabled:        true,
						IngressZone:    "wan",
						Proto:          "tcp",
						ListenPort:     443,
						DestIP:         "10.0.0.11",
						AllowedSources: []string{"203.0.113.128/25"},
					},
				},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected overlapping port-forward validation error")
	}
	cfg.Firewall.NAT.PortForwards[1].AllowedSources = []string{"198.51.100.0/24"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected disjoint port-forwards to be valid, got %v", err)
	}
}

func TestValidateObjects(t *testing.T) {
	cfg := Config{
		Objects: []Object{
			{ID: "host1", Name: "plc-host", Type: ObjectHost, Addresses: []string{"10.0.0.5"}},
			{ID: "net1", Name: "ot-net", Type: ObjectSubnet, Addresses: []string{"10.0.0.0/24"}},
			{ID: "svc1", Name: "modbus", Type: ObjectService, Protocols: []Protocol{{Name: "tcp", Port: "502"}}},
			{ID: "grp1", Name: "ot-assets", Type: ObjectGroup, Members: []string{"host1", "net1"}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid objects, got %v", err)
	}
	cfg.Objects = append(cfg.Objects, Object{ID: "host1", Name: "dup", Type: ObjectHost, Addresses: []string{"10.0.0.6"}})
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected duplicate object id error")
	}
}

func TestValidateVPNListenTargets(t *testing.T) {
	cfg := Config{
		Zones: []Zone{{Name: "wan"}},
		Interfaces: []Interface{
			{Name: "wan0", Device: "eth0", Zone: "wan"},
		},
		Services: ServicesConfig{
			VPN: VPNConfig{
				WireGuard: WireGuardConfig{
					Enabled:          true,
					ListenPort:       51820,
					ListenZone:       "bad-zone",
					ListenInterfaces: []string{"eth0"},
				},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid listenZone error")
	}
	cfg.Services.VPN.WireGuard.ListenZone = "wan"
	cfg.Services.VPN.WireGuard.ListenInterfaces = []string{"missing"}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid listenInterfaces error")
	}
}

func TestValidateDataPlaneConfig(t *testing.T) {
	cfg := Config{
		DataPlane: DataPlaneConfig{
			CaptureInterfaces: []string{"eth0"},
			Enforcement:       true,
			EnforceTable:      "containd",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid dataplane config, got %v", err)
	}
	cfg.DataPlane.EnforceTable = "bad space"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid enforceTable error")
	}
}

func TestValidateProxyConfig(t *testing.T) {
	cfg := Config{
		Services: ServicesConfig{
			Proxy: ProxyConfig{
				Forward: ForwardProxyConfig{Enabled: true, ListenPort: 3128},
				Reverse: ReverseProxyConfig{
					Enabled: true,
					Sites: []ReverseProxySite{
						{Name: "app1", ListenPort: 8443, Backends: []string{"10.0.0.5:443"}},
					},
				},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid proxy config, got %v", err)
	}
	cfg.Services.Proxy.Reverse.Sites[0].Backends = nil
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected reverse proxy backend validation error")
	}
}

func TestValidateMgmtListenAddr(t *testing.T) {
	cfg := Config{
		System: SystemConfig{
			Mgmt: MgmtConfig{ListenAddr: "127.0.0.1:8080"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid mgmt config, got %v", err)
	}
	cfg.System.Mgmt.ListenAddr = string(make([]byte, 200))
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected listenAddr length error")
	}
}
