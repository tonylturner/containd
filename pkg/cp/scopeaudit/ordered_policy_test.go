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
