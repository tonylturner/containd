// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const legacyInterfaceCollisionExport = `{
 "schema_version":"0.1.10",
 "interfaces":[
  {"name":"uplink","device":"eth0","zone":"wan"},
  {"name":"eth0","device":"eth1","zone":"lan"},
  {"name":"vlan10","device":"eth1.10","type":"vlan","parent":"eth0","vlanId":10,"zone":"lan"},
  {"name":"br0","device":"br-old","type":"bridge","members":["eth0"],"zone":"lan"}
 ],
 "zones":[{"name":"wan"},{"name":"lan"}],
 "firewall":{"defaultAction":"DENY"},
 "routing":{"gateways":[{"name":"upstream","address":"192.0.2.1","iface":"eth0"}],
  "routes":[{"dst":"default","gateway":"upstream","iface":"eth0"}]},
 "services":{"vpn":{"wireguard":{"listenInterfaces":["eth0"]},
  "openvpn":{"server":{"tunnelCIDR":"10.8.0.0/24","listenInterfaces":["eth0"]}}},
  "dhcp":{"listenIfaces":["eth0"],"pools":[{"iface":"eth0","start":"10.0.0.2","end":"10.0.0.20"}],
   "reservations":[{"iface":"eth0","mac":"00:11:22:33:44:55","ip":"10.0.0.4"}]}},
 "dataplane":{"captureInterfaces":["eth0"]},
 "pcap":{"interfaces":["eth0"],"forwardTargets":[{"interface":"eth0"}]}
}`

func interfaceCollisionExport(reversed bool) string {
	if !reversed {
		return legacyInterfaceCollisionExport
	}
	return strings.Replace(legacyInterfaceCollisionExport,
		`{"name":"uplink","device":"eth0","zone":"wan"},
  {"name":"eth0","device":"eth1","zone":"lan"}`,
		`{"name":"eth0","device":"eth1","zone":"lan"},
  {"name":"uplink","device":"eth0","zone":"wan"}`, 1)
}

func collisionReferenceValues(cfg *Config) map[string]string {
	return map[string]string{
		"interfaces[vlan10].parent":                       cfg.Interfaces[2].Parent,
		"interfaces[br0].members[0]":                      cfg.Interfaces[3].Members[0],
		"routing.gateways[upstream].iface":                cfg.Routing.Gateways[0].Iface,
		"routing.routes[0].iface":                         cfg.Routing.Routes[0].Iface,
		"services.vpn.wireguard.listenInterfaces[0]":      cfg.Services.VPN.WireGuard.ListenInterfaces[0],
		"services.vpn.openvpn.server.listenInterfaces[0]": cfg.Services.VPN.OpenVPN.Server.ListenInterfaces[0],
		"services.dhcp.pools[0].iface":                    cfg.Services.DHCP.Pools[0].Iface,
		"services.dhcp.reservations[0].iface":             cfg.Services.DHCP.Reservations[0].Iface,
		"services.dhcp.listenIfaces[0]":                   cfg.Services.DHCP.ListenIfaces[0],
		"dataplane.captureInterfaces[0]":                  cfg.DataPlane.CaptureInterfaces[0],
		"pcap.interfaces[0]":                              cfg.PCAP.Interfaces[0],
		"pcap.forwardTargets[0].interface":                cfg.PCAP.ForwardTargets[0].Interface,
	}
}

func assertCollisionUpgrade(t *testing.T, cfg *Config, reversed bool) map[string]string {
	t.Helper()
	vpn := "eth0"
	if reversed {
		vpn = "uplink"
	}
	want := map[string]string{
		"interfaces[vlan10].parent":                       "eth0",
		"interfaces[br0].members[0]":                      "eth0",
		"routing.gateways[upstream].iface":                "uplink",
		"routing.routes[0].iface":                         "uplink",
		"services.vpn.wireguard.listenInterfaces[0]":      vpn,
		"services.vpn.openvpn.server.listenInterfaces[0]": vpn,
		"services.dhcp.pools[0].iface":                    "eth0",
		"services.dhcp.reservations[0].iface":             "eth0",
		"services.dhcp.listenIfaces[0]":                   "eth0",
		"dataplane.captureInterfaces[0]":                  "uplink",
		"pcap.interfaces[0]":                              "eth0",
		"pcap.forwardTargets[0].interface":                "uplink",
	}
	for path, got := range collisionReferenceValues(cfg) {
		if got != want[path] {
			t.Errorf("%s = %q, want %q", path, got, want[path])
		}
	}
	if cfg.SchemaVersion != "0.1.11" {
		t.Errorf("schema = %q", cfg.SchemaVersion)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("upgraded config invalid: %v", err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil || strings.Contains(string(raw), `"device"`) {
		t.Errorf("export retained device: %s %v", raw, err)
	}
	return want
}

func assertCollisionEvidence(t *testing.T, changes []InterfaceDeviceChange, want map[string]string) {
	t.Helper()
	for path, row := range want {
		ambiguous, rewritten := 0, 0
		for _, change := range changes {
			if change.Path != path {
				continue
			}
			switch change.Action {
			case "ambiguous":
				ambiguous++
			case "rewrite":
				rewritten++
			default:
				t.Errorf("unexpected reference action: %+v", change)
			}
			if change.Old != "eth0" || change.New != row {
				t.Errorf("incorrect reference evidence: %+v, want chosen row %q", change, row)
			}
		}
		if ambiguous != 1 {
			t.Errorf("%s has %d ambiguous reference records, want 1", path, ambiguous)
		}
		wantRewrites := 0
		if row != "eth0" {
			wantRewrites = 1
		}
		if rewritten != wantRewrites {
			t.Errorf("%s has %d rewrites, want %d", path, rewritten, wantRewrites)
		}
	}
}

func TestInterfaceDeviceCollisionImport(t *testing.T) {
	for _, reversed := range []bool{false, true} {
		name := "saved_order"
		if reversed {
			name = "reversed_order"
		}
		t.Run(name, func(t *testing.T) {
			cfg, err := DecodeRequestConfig([]byte(interfaceCollisionExport(reversed)), RequestConfigImport)
			if err != nil {
				t.Fatal(err)
			}
			if err := UpgradeInPlace(cfg); err != nil {
				t.Fatal(err)
			}
			want := assertCollisionUpgrade(t, cfg, reversed)
			if cfg.deviceMigration == nil {
				t.Fatal("missing migration evidence")
			}
			assertCollisionEvidence(t, cfg.deviceMigration.Changes, want)
			before, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			evidence := cfg.deviceMigration
			if err := UpgradeInPlace(cfg); err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(cfg)
			if err != nil || string(before) != string(after) || evidence != cfg.deviceMigration {
				t.Fatal("second upgrade changed config or evidence", err)
			}
		})
	}
}

func TestInterfaceDeviceCollisionReopen(t *testing.T) {
	ctx := context.Background()
	for _, reversed := range []bool{false, true} {
		name := "saved_order"
		if reversed {
			name = "reversed_order"
		}
		t.Run(name, func(t *testing.T) {
			s := candidateStore(t)
			for _, bank := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
				if _, err := s.db.Exec(`REPLACE INTO configs (key,data,updated_at) VALUES (?,?,0)`,
					bank, interfaceCollisionExport(reversed)); err != nil {
					t.Fatal(err)
				}
			}
			markLegacyIdentity(t, s)
			s = reopenSnapshotStore(t, s)
			records, err := s.InterfaceDeviceMigrations(ctx)
			if err != nil || len(records) != 3 {
				t.Fatal("missing bank evidence", records, err)
			}
			for _, rec := range records {
				cfg, err := readKindUnupgradedFrom(ctx, s.db, rec.Bank, true)
				if err != nil {
					t.Fatal(err)
				}
				want := assertCollisionUpgrade(t, cfg, reversed)
				assertCollisionEvidence(t, rec.Changes, want)
			}
			before := resetConfigRows(t, s)
			s = reopenSnapshotStore(t, s)
			if after := resetConfigRows(t, s); !reflect.DeepEqual(before, after) {
				t.Fatal("reopen changed stored config or evidence")
			}
			after, err := s.InterfaceDeviceMigrations(ctx)
			if err != nil || !reflect.DeepEqual(records, after) {
				t.Fatal("reopen changed migration evidence", err)
			}
		})
	}
}
