// SPDX-License-Identifier: Apache-2.0
package scopeaudit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestForwardWarningsDurableAtUpgradeAndPublish(t *testing.T) {
	for _, path := range []string{"upgrade", "publish"} {
		t.Run(path, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			db := filepath.Join(dir, "config.db")
			s, err := config.NewSQLiteStore(db)
			if err != nil {
				t.Fatal(err)
			}
			c := config.DefaultConfig()
			if path == "upgrade" {
				c.SchemaVersion = "0.1.9"
			}
			c.DataPlane.DPIMode, c.DataPlane.NFQueueGroup = "enforce", 101
			c.Firewall.NAT.PortForwards = []config.PortForward{{ID: "process", Enabled: true, IngressZone: "wan", Proto: "tcp",
				ListenPort: 1502, DestIP: "10.0.0.8", DestPort: 502, AllowedSources: []string{"198.51.100.0/24"}}}
			c.Firewall.Rules = []config.Rule{
				{ID: "b", Action: config.ActionDeny, Sources: []string{"198.51.100.0/25"}, ICS: config.ICSPredicate{Protocol: "modbus"}},
				{ID: "a", Action: config.ActionAllow, Sources: []string{"198.51.100.0/25"}, ICS: config.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}}},
			}
			if err := s.SaveCandidate(ctx, c); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = config.NewSQLiteStore(db)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			log, err := audit.NewSQLiteStore(filepath.Join(dir, "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			var eventsCount int
			for range 2 {
				events, err := Publish(ctx, s, log)
				if err != nil {
					t.Fatal(err)
				}
				eventsCount = len(events)
			}
			rows, err := log.List(ctx, 100)
			if err != nil || len(rows) != 1 || eventsCount != 1 {
				t.Fatal("delivery lost or duplicated", rows, eventsCount, err)
			}
			wantKind := ForwardWarningKind
			if path == "upgrade" {
				wantKind = OrderedPolicyKind
			}
			if rows[0].Action != wantKind {
				t.Fatal(rows)
			}
			var rec config.OrderedPolicyMigration
			if err := json.Unmarshal([]byte(rows[0].Detail), &rec); err != nil {
				t.Fatal(err)
			}
			if rec.Bank != "candidate" || len(rec.Warnings) != 1 {
				t.Fatal(rec)
			}
			w := rec.Warnings[0]
			if w.ForwardID != "process" || !reflect.DeepEqual(w.RuleIDs, []string{"a", "b"}) ||
				w.Traffic.Backend != "10.0.0.8:502" || w.Traffic.Protocol != "tcp" ||
				w.Traffic.IngressZone != "wan" || !reflect.DeepEqual(w.Traffic.Sources, []string{"198.51.100.0/24"}) {
				t.Fatal("warning lost scope", w)
			}
			if path == "upgrade" && (!reflect.DeepEqual(rec.Before, []string{"b", "a"}) ||
				!reflect.DeepEqual(rec.After, []string{"a", "b"}) || rec.SchemaBefore != "0.1.9") {
				t.Fatal("upgrade lost before/after order", rec)
			}
		})
	}
}

func TestIndustrialAndOrderedEventsCoexist(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := config.NewSQLiteStore(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := config.DefaultConfig()
	c.SchemaVersion = "0.1.7"
	for i := range c.IDS.Rules {
		if c.IDS.Rules[i].Proto == "cip" {
			c.IDS.Rules[i].Proto = "enip"
		}
	}
	// Historical stock content must remain independent of today's catalog.
	c.IDS.Rules = append(c.IDS.Rules, config.IDSRule{
		ID: "IDS-S7-001", Title: "S7comm PLC Stop",
		Description: "S7comm Stop CPU (FC 0x29) halts PLC program execution.",
		Proto:       "s7comm", Severity: "critical", Message: "S7comm PLC stop command detected",
		When:   config.IDSCondition{Field: "attr.function_code", Op: "equals", Value: float64(0x29)},
		Labels: map[string]string{"mitre": "T0881", "category": "ics"},
	})
	if err := s.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	running, err := s.Load(ctx)
	if err != nil || len(running.IDS.Rules) != len(config.DefaultIDSConfig().Rules) {
		t.Fatal("stock IDS bank did not migrate", running, err)
	}
	log, err := audit.NewSQLiteStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	for range 2 {
		events, err := Publish(ctx, s, log)
		if err != nil {
			t.Fatal(err)
		}
		kinds := map[string]int{}
		for _, event := range events {
			kinds[event.Kind]++
			if event.Kind == Kind {
				if !reflect.DeepEqual(event.Attributes["removedRuleIds"], []string{"IDS-S7-001"}) ||
					len(event.Attributes["updatedRuleIds"].([]string)) != 2 {
					t.Fatal("industrial migration evidence lost", event)
				}
			}
		}
		if len(events) != 2 || kinds[Kind] != 1 || kinds[OrderedPolicyKind] != 1 {
			t.Fatal("combined upgrade did not retain both event kinds", events)
		}
	}
	rows, err := log.List(ctx, 100)
	if err != nil || len(rows) != 2 {
		t.Fatal("combined upgrade lost or duplicated audit records", rows, err)
	}
}
