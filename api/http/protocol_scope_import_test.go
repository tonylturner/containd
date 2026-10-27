// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/scopeaudit"
)

func historicalScopeRule() config.IDSRule {
	return config.IDSRule{
		ID: "IDS-S7-001", Title: "S7comm PLC Stop",
		Description: "S7comm Stop CPU (FC 0x29) halts PLC program execution.",
		Proto:       "s7comm", Severity: "critical", Message: "S7comm PLC stop command detected",
		When:   config.IDSCondition{Field: "attr.function_code", Op: "equals", Value: float64(0x29)},
		Labels: map[string]string{"mitre": "T0881", "category": "ics"},
	}
}

func TestProtocolScopeLegacyImport(t *testing.T) {
	resetTestRateLimiters()
	ctx := context.Background()
	for _, path := range []string{"/config/import", "/config"} {
		t.Run(path, func(t *testing.T) {
			store := stageStore(t)
			log, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			server := NewServer(store, log)
			cfg := config.DefaultConfig()
			cfg.SchemaVersion = "0.1.7"
			cfg.IDS.Rules = append(cfg.IDS.Rules, historicalScopeRule())
			rec := requestStage(t, server, "POST", path, cfg)
			if rec.Code != http.StatusOK {
				t.Fatalf("stock import: %d %s", rec.Code, rec.Body)
			}
			got, err := store.LoadCandidate(ctx)
			if err != nil || got.SchemaVersion != config.SchemaVersionCurrent || len(got.IDS.Rules) != len(config.DefaultIDSConfig().Rules) {
				t.Fatalf("staged: %+v %v", got, err)
			}
			rows, err := log.List(ctx, 100)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, row := range rows {
				if row.Action == scopeaudit.Kind && row.Target == "IDS-S7-001" {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("migration audits: %+v", rows)
			}
			records, err := store.IndustrialScopeMigrations(ctx)
			if err != nil || len(records) != 1 {
				t.Fatalf("outbox: %+v %v", records, err)
			}
			for _, endpoint := range []string{"/events", fmt.Sprintf("/events/%d", records[0].ID)} {
				rec = requestStage(t, server, "GET", endpoint, nil)
				if rec.Code != 200 || !strings.Contains(rec.Body.String(), scopeaudit.Kind) || !strings.Contains(rec.Body.String(), "IDS-S7-001") {
					t.Fatalf("event: %d %s", rec.Code, rec.Body)
				}
			}
			for _, version := range []string{"0.1.7", config.SchemaVersionCurrent} {
				cfg.SchemaVersion = version
				rule := historicalScopeRule()
				if version == "0.1.7" {
					rule.Title += " edited"
				}
				cfg.IDS.Rules = append(config.DefaultIDSConfig().Rules, rule)
				rec = requestStage(t, server, "POST", path, cfg)
				var body struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				want := `ids rule IDS-S7-001 proto "s7comm" is not supported; supported: modbus, dnp3, iec104, cip`
				if rec.Code != 400 || body.Error != want {
					t.Fatalf("rejected import: %d %s", rec.Code, rec.Body)
				}
			}
			records, err = store.IndustrialScopeMigrations(ctx)
			if err != nil || len(records) != 1 {
				t.Fatalf("rejected imports wrote migration: %+v %v", records, err)
			}
		})
	}
}
