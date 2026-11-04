// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

const interfaceDeviceMigrationKey = "interface_device_migration_0111"

type InterfaceDeviceChange struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	Old    string `json:"old"`
	New    string `json:"new,omitempty"`
}

// InterfaceDeviceMigration records discarded bindings and normalized references.
// It remains export-independent evidence, including for invalid legacy row names.
type InterfaceDeviceMigration struct {
	ID           uint64                  `json:"id"`
	Timestamp    time.Time               `json:"timestamp"`
	Bank         string                  `json:"bank"`
	SchemaBefore string                  `json:"schemaBefore"`
	SchemaAfter  string                  `json:"schemaAfter"`
	Changes      []InterfaceDeviceChange `json:"changes"`
}

func beforeInterfaceNames(schema string) bool {
	v, err := parseSemver(schema)
	return schema == "" || err == nil && compareSemver(v, semver{minor: 1, patch: 11}) < 0
}

// Read only at the decode boundary: legacy bindings never enter the row model.
func readLegacyInterfaceDevices(raw []byte, cfg *Config) error {
	if !beforeInterfaceNames(cfg.SchemaVersion) {
		return nil
	}
	var legacy struct {
		Interfaces []struct {
			Device string `json:"device"`
		} `json:"interfaces"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return err
	}
	cfg.legacyDevices = make([]string, len(legacy.Interfaces))
	for i, row := range legacy.Interfaces {
		cfg.legacyDevices[i] = row.Device
	}
	return nil
}

func upgradeInterfaceNames(cfg *Config, schema string) {
	rec := &InterfaceDeviceMigration{Timestamp: time.Now().UTC(), SchemaBefore: schema, SchemaAfter: "0.1.11"}
	rec.ID = uint64(rec.Timestamp.UnixNano())
	refs, ambiguous := map[string]string{}, map[string]bool{}
	for i, row := range cfg.Interfaces {
		path := fmt.Sprintf("interfaces[%s]", row.Name)
		if err := enforce.ValidateInterfaceName(row.Name); err != nil {
			rec.Changes = append(rec.Changes, InterfaceDeviceChange{Path: path + ".name", Action: "invalid", Old: row.Name})
		}
		if i >= len(cfg.legacyDevices) || cfg.legacyDevices[i] == "" {
			continue
		}
		dev := cfg.legacyDevices[i]
		rec.Changes = append(rec.Changes, InterfaceDeviceChange{Path: path + ".device", Action: "drop", Old: dev})
		if previous, ok := refs[dev]; ok && previous != row.Name {
			ambiguous[dev] = true
		}
		refs[dev] = row.Name
	}
	rewrite := func(path string, ref *string) {
		if name, ok := refs[*ref]; ok && !ambiguous[*ref] && name != *ref {
			rec.Changes = append(rec.Changes, InterfaceDeviceChange{Path: path, Action: "rewrite", Old: *ref, New: name})
			*ref = name
		}
	}
	list := func(path string, refs []string) {
		for i := range refs {
			rewrite(fmt.Sprintf("%s[%d]", path, i), &refs[i])
		}
	}
	for i := range cfg.Interfaces {
		row := &cfg.Interfaces[i]
		rewrite(fmt.Sprintf("interfaces[%s].parent", row.Name), &row.Parent)
		list(fmt.Sprintf("interfaces[%s].members", row.Name), row.Members)
	}
	for i := range cfg.Routing.Gateways {
		rewrite(fmt.Sprintf("routing.gateways[%s].iface", cfg.Routing.Gateways[i].Name), &cfg.Routing.Gateways[i].Iface)
	}
	for i := range cfg.Routing.Routes {
		rewrite(fmt.Sprintf("routing.routes[%d].iface", i), &cfg.Routing.Routes[i].Iface)
	}
	list("services.vpn.wireguard.listenInterfaces", cfg.Services.VPN.WireGuard.ListenInterfaces)
	if server := cfg.Services.VPN.OpenVPN.Server; server != nil {
		list("services.vpn.openvpn.server.listenInterfaces", server.ListenInterfaces)
	}
	for i := range cfg.Services.DHCP.Pools {
		rewrite(fmt.Sprintf("services.dhcp.pools[%d].iface", i), &cfg.Services.DHCP.Pools[i].Iface)
	}
	for i := range cfg.Services.DHCP.Reservations {
		rewrite(fmt.Sprintf("services.dhcp.reservations[%d].iface", i), &cfg.Services.DHCP.Reservations[i].Iface)
	}
	for i := range cfg.PCAP.ForwardTargets {
		rewrite(fmt.Sprintf("pcap.forwardTargets[%d].interface", i), &cfg.PCAP.ForwardTargets[i].Interface)
	}
	list("services.dhcp.listenIfaces", cfg.Services.DHCP.ListenIfaces)
	list("dataplane.captureInterfaces", cfg.DataPlane.CaptureInterfaces)
	list("pcap.interfaces", cfg.PCAP.Interfaces)
	cfg.legacyDevices = nil
	if len(rec.Changes) > 0 {
		cfg.deviceMigration = rec
	}
}

func readInterfaceDeviceMigrations(ctx context.Context, db configReader) ([]InterfaceDeviceMigration, error) {
	var raw string
	err := db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, interfaceDeviceMigrationKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []InterfaceDeviceMigration
	err = json.Unmarshal([]byte(raw), &records)
	return records, err
}

func (s *SQLiteStore) InterfaceDeviceMigrations(ctx context.Context) ([]InterfaceDeviceMigration, error) {
	return readInterfaceDeviceMigrations(ctx, s.db)
}

func persistInterfaceDeviceMigrationTx(ctx context.Context, tx *sql.Tx, bank string, rec *InterfaceDeviceMigration) error {
	if rec == nil {
		return nil
	}
	records, err := readInterfaceDeviceMigrations(ctx, tx)
	if err != nil {
		return err
	}
	for _, old := range records {
		if old.ID == rec.ID && old.Bank == bank {
			return nil
		}
	}
	detached := *rec
	detached.Bank = bank
	records = append(records, detached)
	blob, err := json.Marshal(records)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,?)`, interfaceDeviceMigrationKey, string(blob), rec.Timestamp.Unix())
	return err
}
