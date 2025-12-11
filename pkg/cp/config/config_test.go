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
			DefaultAction: ActionAllow,
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
