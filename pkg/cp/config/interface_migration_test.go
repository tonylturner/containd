// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const legacyInterfaceExport = `{
 "schema_version":"0.1.10",
 "interfaces":[
  {"name":"wan","device":"eth0","zone":"wan"},
  {"name":"lan","device":"eth1","zone":"lan"},
  {"name":"vlan10","device":"eth1.10","type":"vlan","parent":"eth1","vlanId":10,"zone":"lan"},
  {"name":"br0","device":"br-old","type":"bridge","members":["eth1.10"],"zone":"lan"}
 ],
 "zones":[{"name":"wan"},{"name":"lan"}],
 "firewall":{"defaultAction":"DENY"},
 "routing":{"gateways":[{"name":"upstream","address":"192.0.2.1","iface":"eth0"}],
  "routes":[{"dst":"default","gateway":"upstream","iface":"eth0"}]},
 "services":{"vpn":{"wireguard":{"listenInterfaces":["eth0"]},
  "openvpn":{"server":{"tunnelCIDR":"10.8.0.0/24","listenInterfaces":["eth1"]}}},
  "dhcp":{"listenIfaces":["eth1","literal0"],"pools":[{"iface":"eth1","start":"10.0.0.2","end":"10.0.0.20"}],"reservations":[{"iface":"eth1","mac":"00:11:22:33:44:55","ip":"10.0.0.4"}]}},
 "dataplane":{"captureInterfaces":["eth0","literal0"]},
 "pcap":{"interfaces":["eth1","literal0"],"forwardTargets":[{"interface":"eth1"}]}
}`

func assertInterfaceUpgrade(t *testing.T, cfg *Config) {
	t.Helper()
	if cfg.SchemaVersion != "0.1.11" || cfg.Routing.Gateways[0].Iface != "wan" || cfg.Routing.Routes[0].Iface != "wan" ||
		cfg.Services.DHCP.Pools[0].Iface != "lan" || cfg.Services.DHCP.Reservations[0].Iface != "lan" || cfg.PCAP.ForwardTargets[0].Interface != "lan" || cfg.Interfaces[2].Parent != "lan" || cfg.Interfaces[3].Members[0] != "vlan10" ||
		cfg.Services.VPN.WireGuard.ListenInterfaces[0] != "wan" || cfg.Services.VPN.OpenVPN.Server.ListenInterfaces[0] != "lan" ||
		!reflect.DeepEqual(cfg.Services.DHCP.ListenIfaces, []string{"lan", "literal0"}) ||
		!reflect.DeepEqual(cfg.DataPlane.CaptureInterfaces, []string{"wan", "literal0"}) ||
		!reflect.DeepEqual(cfg.PCAP.Interfaces, []string{"lan", "literal0"}) {
		t.Fatalf("references not normalized: %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil || strings.Contains(string(raw), `"device"`) {
		t.Fatalf("export retained device: %s %v", raw, err)
	}
}

func TestInterfaceDeviceImportUpgrade(t *testing.T) {
	cfg, err := DecodeRequestConfig([]byte(legacyInterfaceExport), RequestConfigImport)
	if err != nil {
		t.Fatal(err)
	}
	if err := UpgradeInPlace(cfg); err != nil {
		t.Fatal(err)
	}
	assertInterfaceUpgrade(t, cfg)
	if cfg.deviceMigration == nil || len(cfg.deviceMigration.Changes) != 16 {
		t.Fatalf("missing changes: %+v", cfg.deviceMigration)
	}
	if cfg.orderMigration != nil {
		t.Fatal("0.1.10 policy reordered")
	}
	evidence := cfg.deviceMigration
	if err := UpgradeInPlace(cfg); err != nil || evidence != cfg.deviceMigration {
		t.Fatal("upgrade repeated", err)
	}
	s := candidateStore(t)
	if err := testSaveCandidate(s, context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	records, err := s.InterfaceDeviceMigrations(context.Background())
	if err != nil || len(records) != 1 || records[0].Bank != configKeyCandidate {
		t.Fatal("import evidence lost", records, err)
	}
}

func TestInterfaceDeviceStoreOpenUpgradeAndReopen(t *testing.T) {
	ctx := context.Background()
	s := candidateStore(t)
	for _, bank := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
		if _, err := s.db.Exec(`REPLACE INTO configs (key,data,updated_at) VALUES (?,?,0)`, bank, legacyInterfaceExport); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(time.Hour).UnixNano()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`REPLACE INTO configs (key,data,updated_at) VALUES (?,?,0)`, configKeyPending, string(pending)); err != nil {
		t.Fatal(err)
	}
	markLegacyIdentity(t, s)
	s = reopenSnapshotStore(t, s)
	for _, bank := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
		cfg, err := readKindUnupgradedFrom(ctx, s.db, bank, true)
		if err != nil {
			t.Fatal(err)
		}
		assertInterfaceUpgrade(t, cfg)
	}
	records, err := s.InterfaceDeviceMigrations(ctx)
	if err != nil || len(records) != 3 {
		t.Fatal("missing durable bank evidence", records, err)
	}
	for _, rec := range records {
		if rec.SchemaBefore != "0.1.10" || rec.SchemaAfter != "0.1.11" || len(rec.Changes) != 16 {
			t.Fatalf("incomplete evidence: %+v", rec)
		}
	}
	before := resetConfigRows(t, s)
	s = reopenSnapshotStore(t, s)
	if after := resetConfigRows(t, s); !reflect.DeepEqual(before, after) {
		t.Fatal("reopen mutated stored rows")
	}
	next, err := s.loadPending(ctx)
	if err != nil || next.DeadlineUnix == 0 {
		t.Fatal("pending confirmation lost", err)
	}
}

func TestInterfaceDeviceMigrationInvalidName(t *testing.T) {
	raw := strings.ReplaceAll(legacyInterfaceExport, `"name":"lan"`, `"name":"Plant Floor"`)
	cfg, err := DecodeRequestConfig([]byte(raw), RequestConfigImport)
	if err != nil {
		t.Fatal(err)
	}
	if err := UpgradeInPlace(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid interface name") {
		t.Fatal("invalid row accepted", err)
	}
	found := false
	for _, change := range cfg.deviceMigration.Changes {
		found = found || change.Action == "invalid" && change.Old == "Plant Floor"
	}
	if !found {
		t.Fatal("invalid name absent from evidence")
	}
	s := candidateStore(t)
	if _, err := s.db.Exec(`UPDATE configs SET data=? WHERE key=?`, raw, configKeyRunning); err != nil {
		t.Fatal(err)
	}
	s = reopenSnapshotStore(t, s)
	records, err := s.InterfaceDeviceMigrations(context.Background())
	if err != nil || len(records) != 1 {
		t.Fatal("invalid row evidence not persisted", records, err)
	}
	cfg, err = s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("stored invalid name accepted")
	}
}

func TestInterfaceDeviceExpiredPendingRollback(t *testing.T) {
	ctx := context.Background()
	s := candidateStore(t)
	if _, err := s.db.Exec(`REPLACE INTO configs (key,data,updated_at) VALUES (?,?,0)`, configKeyPrevious, legacyInterfaceExport); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(-time.Hour).UnixNano()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`REPLACE INTO configs (key,data,updated_at) VALUES (?,?,0)`, configKeyPending, string(raw)); err != nil {
		t.Fatal(err)
	}
	markLegacyIdentity(t, s)
	s = reopenSnapshotStore(t, s)
	restored, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertInterfaceUpgrade(t, restored)
	records, err := s.InterfaceDeviceMigrations(ctx)
	if err != nil || len(records) != 1 || records[0].Bank != configKeyPrevious {
		t.Fatal("pending rollback evidence lost", records, err)
	}
}
