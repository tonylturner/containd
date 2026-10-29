// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestICSSelectorCreateCommitReload(t *testing.T) {
	resetTestRateLimiters()
	path := filepath.Join(t.TempDir(), "config.db")
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	cfg := config.DefaultConfig()
	cfg.DataPlane.DPIEnabled = true
	cfg.DataPlane.NFQueueGroup = 100
	cfg.Firewall.Rules = nil
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	engine := &stageEngine{mockEngine: &mockEngine{}}
	server := NewServerWithEngine(store, nil, engine)
	predicates := []config.ICSPredicate{
		{Protocol: "modbus", FunctionCode: []uint8{0}, UnitID: new(uint8(0)), Addresses: []string{"0"}},
		{Protocol: "iec104", TypeIDs: []int{45}, Classes: []string{"control"}, CA: []uint16{0},
			IOA: []config.IOARange{{Start: 0, End: 0}}, COT: []int{1, 63}, Originators: []int{0},
			Negative: new(false), Test: new(false), SelectExecute: "execute"},
		{Protocol: "dnp3", FunctionCode: []uint8{0}, Masters: []uint16{0, 65519}, Outstations: []uint16{0},
			Groups: []int{0}, Variations: []int{0}, Addresses: []string{"0-4294967295"}},
		{Protocol: "cip", FunctionCode: []uint8{0}, ObjectClasses: []uint16{0}, Instances: []uint16{0}, Attributes: []uint16{0}},
		{Protocol: "cip", Tags: []string{"Program:Main.Tag.Member"}},
	}
	var want []config.Rule
	for i, predicate := range predicates {
		rule := config.Rule{ID: string(rune('a' + i)), Action: config.ActionAllow, ICS: predicate}
		want = append(want, rule)
		rec := requestStage(t, server, http.MethodPost, "/firewall/ics-rules", rule)
		if rec.Code != http.StatusOK {
			t.Fatalf("create: %d %s", rec.Code, rec.Body)
		}
	}
	rec := requestStage(t, server, http.MethodGet, "/config/candidate", nil)
	var candidate config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &candidate); err != nil || rec.Code != http.StatusOK ||
		!reflect.DeepEqual(candidate.Firewall.Rules, want) {
		t.Fatalf("candidate lost selectors: %s %v", rec.Body, err)
	}
	running, err := store.Load(ctx)
	if err != nil || len(running.Firewall.Rules) != 0 {
		t.Fatalf("create changed running: %+v %v", running, err)
	}
	rec = requestStage(t, server, http.MethodPost, "/config/commit", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	running, err = reopened.Load(ctx)
	if err != nil || !reflect.DeepEqual(running.Firewall.Rules, want) {
		t.Fatalf("reload lost selectors: %+v %v", running, err)
	}
	// Inspect both the snapshot actually sent on commit and a fresh post-reload
	// compile. Compare each field independently: the CP and DP wire objects
	// intentionally use different names for the older generic fields.
	recompiled, err := compile.CompileSnapshot(running)
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []rules.Snapshot{engine.snap, recompiled} {
		if len(snapshot.Firewall) != len(want) {
			t.Fatalf("snapshot has %d entries, want %d", len(snapshot.Firewall), len(want))
		}
		for i, entry := range snapshot.Firewall {
			if entry.ID != want[i].ID {
				t.Fatalf("snapshot ID %s, want %s", entry.ID, want[i].ID)
			}
			cp := reflect.ValueOf(want[i].ICS)
			dp := reflect.ValueOf(entry.ICS)
			for field := range cp.NumField() {
				name := cp.Type().Field(field).Name
				got, err := json.Marshal(dp.FieldByName(name).Interface())
				if err != nil {
					t.Fatal(err)
				}
				expected, err := json.Marshal(cp.Field(field).Interface())
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != string(expected) {
					t.Fatalf("snapshot %s lost %s: %s, want %s", entry.ID, name, got, expected)
				}
			}
		}
	}
}

func TestICSPatchRoutesHaveDistinctSemantics(t *testing.T) {
	// PATCH /firewall/rules/:id merges ICS; PATCH /firewall/ics-rules/:id
	// replaces the entire rule, so omitted ICS selectors become ANY.
	for _, route := range []string{"/api/v1/firewall/rules/r1", "/api/v1/firewall/ics-rules/r1"} {
		t.Run(route, func(t *testing.T) {
			initial := config.ICSPredicate{Protocol: "iec104", TypeIDs: []int{45}, COT: []int{6}, Negative: new(false)}
			store := iecPatchStore(initial)
			server := NewServer(store, nil)
			rec := strictRuleRequest(t, server, http.MethodPatch, route, `{"action":"ALLOW","ics":{"protocol":"iec104","test":false}}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", route, rec.Code, rec.Body)
			}
			want := config.ICSPredicate{Protocol: "iec104", Test: new(false)}
			if route == "/api/v1/firewall/rules/r1" {
				want = initial
				want.Test = new(false)
			}
			if !reflect.DeepEqual(store.cfg.Firewall.Rules[0].ICS, want) {
				t.Fatalf("%s changed semantics: %+v want %+v", route, store.cfg.Firewall.Rules[0].ICS, want)
			}
			rec = strictRuleRequest(t, server, http.MethodPatch, route, `{"action":"ALLOW","ics":{"protocol":"iec104","typeIds":null,"cot":null,"negative":null,"test":null}}`)
			if route == "/api/v1/firewall/rules/r1" {
				if rec.Code != http.StatusOK || !reflect.DeepEqual(store.cfg.Firewall.Rules[0].ICS, config.ICSPredicate{Protocol: "iec104"}) {
					t.Fatalf("merge null clear: %d %s", rec.Code, rec.Body)
				}
			} else if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "must not be null") {
				t.Fatalf("replacement accepted null: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestICSPreviewRejectsSemanticSelectors(t *testing.T) {
	for _, selector := range []string{
		`{"protocol":"dnp3","unitId":0}`,
		`{"protocol":"cip","unitId":0}`,
		`{"protocol":"dnp3","addresses":["0"]}`,
		`{"protocol":"cip","tags":["Bad[0]"]}`,
		`{"protocol":"iec104","typeIds":[51],"selectExecute":"select"}`,
	} {
		server := NewServer(iecPatchStore(config.ICSPredicate{}), nil)
		rec := strictRuleRequest(t, server, http.MethodPost, "/api/v1/firewall/rules/preview",
			`{"id":"preview","action":"ALLOW","ics":`+selector+`}`)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "ics") {
			t.Fatalf("preview %s: %d %s", selector, rec.Code, rec.Body)
		}
	}
}
