// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	engineapi "github.com/tonylturner/containd/api/engine"
	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"go.uber.org/zap"
)

// Historical fixture, independent of the active builtin catalog.
func oldScopeBuiltin() config.IDSRule {
	return config.IDSRule{
		ID: "IDS-S7-001", Title: "S7comm PLC Stop",
		Description: "S7comm Stop CPU (FC 0x29) halts PLC program execution.",
		Proto:       "s7comm", Severity: "critical", Message: "S7comm PLC stop command detected",
		When:   config.IDSCondition{Field: "attr.function_code", Op: "equals", Value: float64(0x29)},
		Labels: map[string]string{"mitre": "T0881", "category": "ics"},
	}
}

func seedOldScopeConfig(t *testing.T, path string, edit func(*config.Config)) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw string
	if err := db.QueryRow(`SELECT data FROM configs WHERE key = 'running'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Bank int64 `json:"ids_bank"`
	}
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		t.Fatal(err)
	}
	cfg.SchemaVersion = "0.1.7"
	cfg.IDS.Rules = append(config.DefaultIDSConfig().Rules, oldScopeBuiltin())
	for i, rule := range cfg.IDS.Rules {
		if rule.Proto == "cip" {
			cfg.IDS.Rules[i].Proto = "enip"
		}
	}
	edit(&cfg)
	bank, err := json.Marshal(cfg.IDS.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE ids_banks SET data = ? WHERE id = ?`, string(bank), meta.Bank); err != nil {
		t.Fatal(err)
	}
	cfg.IDS.Rules = nil
	doc, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(doc, &fields); err != nil {
		t.Fatal(err)
	}
	fields["ids_bank"] = json.RawMessage(fmt.Sprint(meta.Bank))
	fields["snapshot_format"] = json.RawMessage("3")
	doc, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE configs SET data = ? WHERE key = 'running'`, string(doc)); err != nil {
		t.Fatal(err)
	}
}

func TestRemovedProtocolBootRecovery(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		for _, scenario := range []string{"rule", "toggle", "edited-bank", "edited-cip", "stock-bank"} {
			t.Run(fmt.Sprintf("reserved=%t/%s", reserved, scenario), func(t *testing.T) {
				ctx := context.Background()
				dir := t.TempDir()
				path := filepath.Join(dir, "config.db")
				t.Setenv("CONTAIND_CONFIG_DB", path)
				t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(dir, "audit.db"))
				t.Setenv("CONTAIND_USERS_DB", filepath.Join(dir, "users.db"))
				store, err := config.NewSQLiteStore(path)
				if err != nil {
					t.Fatal(err)
				}
				cfg := config.DefaultConfig()
				cfg.Interfaces = []config.Interface{{Name: "custom", Device: "scope-test", Zone: "lan"}}
				cfg.DataPlane.Enforcement = true
				if err := store.Save(ctx, cfg); err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				want := ""
				seedOldScopeConfig(t, path, func(c *config.Config) {
					switch scenario {
					case "rule":
						c.Firewall.Rules = []config.Rule{{ID: "saved-rule", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "mms"}}}
						want = `rule saved-rule ics protocol "mms" is not supported`
					case "toggle":
						c.DataPlane.DPIICSProtocols = map[string]bool{"bacnet": false}
						want = `dataplane.dpiIcsProtocols: protocol "bacnet" is not supported`
					case "edited-cip":
						for i, rule := range c.IDS.Rules {
							if rule.ID == "IDS-CIP-001" {
								c.IDS.Rules[i].Title += " operator edit"
							}
						}
						want = `ids rule IDS-CIP-001 proto "enip": EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`
					case "edited-bank":
						c.IDS.Rules[len(c.IDS.Rules)-1].Title += " operator edit"
						want = `ids rule IDS-S7-001 proto "s7comm" is not supported`
					}
				})
				var r *mgmtpath.Reservation
				if reserved {
					r = &mgmtpath.Reservation{Device: "scope-test", Local: netip.MustParsePrefix("10.99.99.2/24"),
						Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: 8080}
				}
				stores, running, err := initMgmtStores(zap.NewNop().Sugar(), r)
				if err != nil {
					t.Fatalf("boot stopped management: %v", err)
				}
				defer stores.store.Close()
				defer stores.auditStore.Close()
				defer stores.userStore.Close()
				fault, err := config.ManagementBootFaultForStore(ctx, stores.store)
				if err != nil || (want == "" && fault != "") || (want != "" && !strings.Contains(fault, want)) {
					t.Fatalf("fault=%q want=%q err=%v", fault, want, err)
				}
				// Export/read retains exactly the invalid semantic reference.
				exported, err := stores.store.Load(ctx)
				if err != nil || !reflect.DeepEqual(running, exported) {
					t.Fatalf("invalid config not exportable unchanged: %v", err)
				}
				if scenario == "stock-bank" {
					if len(stores.scopeEvents) != 1 || len(stores.scopeEvents[0].Attributes["updatedRuleIds"].([]string)) != 2 || len(running.IDS.Rules) != len(config.DefaultIDSConfig().Rules) {
						t.Fatal("stock bank did not migrate with an event")
					}
					events, err := publishScopeMigrations(ctx, stores)
					if err != nil || !reflect.DeepEqual(events, stores.scopeEvents) {
						t.Fatalf("outbox replay changed event: %v", err)
					}
					rows, err := stores.auditStore.List(ctx, 100)
					if err != nil {
						t.Fatal(err)
					}
					count := 0
					for _, row := range rows {
						if row.Action == "config.industrial_scope.migrated" && strings.Contains(row.Target, "IDS-S7-001") {
							count++
						}
					}
					if count != 1 {
						t.Fatalf("audit records=%d", count)
					}
					return
				}
				switch scenario {
				case "rule":
					if exported.Firewall.Rules[0].ICS.Protocol != "mms" {
						t.Fatal("invalid rule rewritten")
					}
				case "toggle":
					if v, ok := exported.DataPlane.DPIICSProtocols["bacnet"]; !ok || v {
						t.Fatal("invalid false toggle dropped")
					}
				case "edited-cip":
					found := false
					for _, rule := range exported.IDS.Rules {
						if rule.ID == "IDS-CIP-001" {
							found = rule.Proto == "enip" && strings.HasSuffix(rule.Title, " operator edit")
						}
					}
					if !found {
						t.Fatal("edited CIP builtin changed")
					}
				case "edited-bank":
					if exported.IDS.Rules[len(exported.IDS.Rules)-1].Title != oldScopeBuiltin().Title+" operator edit" {
						t.Fatal("edited builtin dropped")
					}
				}
				srv, calls := recordingEngine(t)
				if _, err := httpapi.ApplyBootConfig(ctx, stores.store, engineapi.NewHTTPClient(srv.URL), nil); err != nil {
					t.Fatal(err)
				}
				applied, _ := nextRuleset(t, calls)
				if applied.snapshot.Default != rules.ActionDeny || len(applied.snapshot.Firewall) != 0 ||
					applied.snapshot.Version != config.ManagementRecoveryVersion {
					t.Fatalf("unsafe recovery: %+v", applied.snapshot)
				}
				fixed := *running
				fixed.Firewall.Rules = nil
				fixed.DataPlane.DPIICSProtocols = nil
				fixed.IDS.Rules = config.DefaultIDSConfig().Rules
				if err := stores.store.SaveCandidate(ctx, &fixed); err != nil {
					t.Fatal(err)
				}
				if err := config.CheckManagementBootFault(ctx, stores.store); err == nil {
					t.Fatal("staging repaired recovery without a commit")
				}
				if err := stores.store.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := config.CheckManagementBootFault(ctx, stores.store); err != nil {
					t.Fatalf("explicit valid commit did not repair: %v", err)
				}
				if err := stores.store.Rollback(ctx); err == nil {
					t.Fatal("rollback accepted the incompatible original")
				}
			})
		}
	}
}
