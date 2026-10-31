// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

func TestRemovedProtocolValidation(t *testing.T) {
	for _, name := range []string{"s7comm", "s7", "bacnet", "opcua", "mms", "iec61850", "goose", "enip", " ENiP "} {
		t.Run(name, func(t *testing.T) {
			suffix := " is not supported; supported: " + ics.SupportedNames
			if strings.EqualFold(strings.TrimSpace(name), "enip") {
				suffix = `: EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`
			}
			err := genericICSConfig(name, "monitor", "", 0).Validate()
			want := fmt.Sprintf("rule ics-1 ics protocol %q%s", name, suffix)
			if err == nil || err.Error() != want {
				t.Fatalf("firewall error=%v want=%s", err, want)
			}
			for _, enabled := range []bool{true, false} {
				err := validateDataPlane(DataPlaneConfig{DPIICSProtocols: map[string]bool{name: enabled}})
				want := fmt.Sprintf("dataplane.dpiIcsProtocols: protocol %q%s", name, suffix)
				if err == nil || err.Error() != want {
					t.Fatalf("toggle %t error=%v want=%s", enabled, err, want)
				}
				err = validateIDS(IDSConfig{Rules: []IDSRule{{ID: "custom", Proto: name, Enabled: &enabled}}})
				want = fmt.Sprintf("ids rule custom proto %q%s", name, suffix)
				if err == nil || err.Error() != want {
					t.Fatalf("IDS error=%v want=%s", err, want)
				}
			}
		})
	}
	for _, name := range []string{"modbus", "dnp3", "iec104", "cip"} {
		for _, enabled := range []bool{true, false} {
			if err := validateDataPlane(DataPlaneConfig{DPIICSProtocols: map[string]bool{name: enabled}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{"", "tcp", "udp", "dns", "tls", "http", "ssh", "smb", "ntp", "snmp", "rdp"} {
		if err := validateIDS(IDSConfig{Rules: []IDSRule{{ID: "it", Proto: name}}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, port := range []string{"102", "4840", "47808", "18245"} {
		cfg := DefaultConfig()
		cfg.Firewall.Rules = []Rule{{ID: "numeric", Action: ActionAllow, Protocols: []Protocol{{Name: "tcp", Port: port}}}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("numeric port forbidden: %v", err)
		}
	}
}

func TestRemovedProtocolBuiltinExactMatch(t *testing.T) {
	for _, stock := range append(retiredBuiltinDefinitions(), historicalCIPBuiltinDefinitions()...) {
		for _, enabled := range []*bool{nil, boolRef(true), boolRef(false)} {
			changed := stock
			changed.Enabled = enabled
			if !sameBuiltin(stock, changed) {
				t.Fatalf("enabled flag changed identity: %s", stock.ID)
			}
		}
		// Every serialized field other than enabled participates, not just
		// ID/protocol/condition. This catches operator metadata edits too.
		blob, err := json.Marshal(stock)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(blob, &fields); err != nil {
			t.Fatal(err)
		}
		for key := range fields {
			if key == "enabled" {
				continue
			}
			edited := stock
			v := reflect.ValueOf(&edited).Elem()
			typ := v.Type()
			for i := range typ.NumField() {
				if strings.Split(typ.Field(i).Tag.Get("json"), ",")[0] == key {
					v.Field(i).SetZero()
				}
			}
			if sameBuiltin(stock, edited) {
				t.Fatalf("%s ignored edit to %s", stock.ID, key)
			}
		}
	}
}

func boolRef(v bool) *bool { return &v }

func TestRemovedProtocolStoredBankMigration(t *testing.T) {
	for _, edited := range []bool{false, true} {
		t.Run(fmt.Sprint(edited), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.db")
			s, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			cfg := DefaultConfig()
			if err := s.Save(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			old := retiredBuiltinDefinitions()
			old[0].Enabled = boolRef(false)
			if edited {
				old[0].Description += " operator edit"
			}
			cfg.IDS.Rules = append(cfg.IDS.Rules, old...)
			cfg.SchemaVersion = "0.1.7"
			// Seed a real separately referenced bank behind current validation.
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := replaceIDSRulesTx(ctx, tx, cfg.IDS.Rules); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
				if err := writeConfigTx(ctx, tx, key, cfg); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for _, key := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
				got, err := s.loadKind(ctx, key)
				if err != nil {
					t.Fatalf("saved invalid config unreadable: %v", err)
				}
				if err := got.Validate(); edited != (err != nil) {
					t.Fatalf("edited=%t validation=%v", edited, err)
				}
				for _, r := range got.IDS.Rules {
					if ics.Removed(r.Proto) && (!edited || r.ID != old[0].ID || r.Description != old[0].Description) {
						t.Fatalf("unexpected remaining rule: %+v", r)
					}
				}
			}
			records, err := s.IndustrialScopeMigrations(ctx)
			want := 5
			if edited {
				want--
			}
			if err != nil || len(records) != 1 || len(records[0].Removed) != want {
				t.Fatalf("migration records=%+v err=%v", records, err)
			}
			if again, err := s.MigrateIndustrialScope(ctx); err != nil || again != nil {
				t.Fatalf("migration not idempotent: %+v %v", again, err)
			}
		})
	}
	cfg := &Config{SchemaVersion: SchemaVersionCurrent, IDS: IDSConfig{Rules: retiredBuiltinDefinitions()}}
	if got := removeRetiredBuiltins(cfg); len(got) != 0 {
		t.Fatalf("current-schema import silently migrated: %v", got)
	}
}
