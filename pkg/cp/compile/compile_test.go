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
					Action:      config.ActionAllow,
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
