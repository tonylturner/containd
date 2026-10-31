// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestMergeRulePatch(t *testing.T) {
	existing := config.Rule{
		ID: "r1", Description: "old", Action: config.ActionAllow, Log: true,
		Sources: []string{"10.0.0.1/32"},
		ICS:     config.ICSPredicate{Protocol: "iec104"},
		Schedule: &config.ScheduleConfig{
			DaysOfWeek: []string{"Monday"}, StartTime: "09:00", EndTime: "17:00", Timezone: "UTC",
		},
	}
	for _, tc := range []struct {
		name, body string
		want       config.Rule
	}{
		{"nested fields", `{"schedule":{"endTime":"18:00"},"description":"new","log":false}`,
			config.Rule{
				ID: "r1", Description: "new", Action: config.ActionAllow,
				Sources: existing.Sources, ICS: existing.ICS,
				Schedule: &config.ScheduleConfig{
					DaysOfWeek: []string{"Monday"}, StartTime: "09:00", EndTime: "18:00", Timezone: "UTC",
				},
			}},
		{"null and arrays", `{"schedule":null,"sources":[]}`,
			config.Rule{
				ID: "r1", Description: "old", Action: config.ActionAllow, Log: true,
				Sources: []string{}, ICS: existing.ICS,
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var patch map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.body), &patch); err != nil {
				t.Fatal(err)
			}
			got, err := mergeRulePatch(existing, patch)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("merge = %+v, %v; want %+v", got, err, tc.want)
			}
			if existing.Schedule.EndTime != "17:00" || existing.Sources[0] != "10.0.0.1/32" {
				t.Fatal("patch mutated the original rule")
			}
		})
	}
	for _, body := range []string{
		`{"state":["on"]}`, `{"log":"yes"}`, `{"schedule":{"endTime":42}}`,
	} {
		var patch map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &patch); err != nil {
			t.Fatal(err)
		}
		if _, err := mergeRulePatch(existing, patch); err == nil {
			t.Fatalf("accepted invalid patch %s", body)
		}
	}
}

func iecPatchStore(ics config.ICSPredicate) *mockStore {
	return &mockStore{cfg: &config.Config{
		System:    config.SystemConfig{Hostname: "containd"},
		DataPlane: config.DataPlaneConfig{DPIEnabled: true, NFQueueGroup: 101},
		Firewall: config.FirewallConfig{
			DefaultAction: config.ActionDeny,
			Rules:         []config.Rule{{ID: "r1", Description: "old", ICS: ics, Action: config.ActionAllow}},
		},
	}}
}

func patchRule(t *testing.T, m *mockStore, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPatch, "/api/v1/firewall/rules/r1", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	NewServer(m, nil).ServeHTTP(rec, req)
	return rec
}

func TestPatchFirewallRuleICS(t *testing.T) {
	modbus := config.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, WriteOnly: true}
	iec := config.ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}, Mode: "enforce"}

	t.Run("protocol change replaces the predicate", func(t *testing.T) {
		m := iecPatchStore(modbus)
		rec := patchRule(t, m, `{"ics":{"protocol":"iec104","classes":["control"],"mode":"enforce"}}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
		}
		want := config.ICSPredicate{Protocol: "iec104", Classes: []string{"control"}, Mode: "enforce"}
		if got := m.cfg.Firewall.Rules[0].ICS; !reflect.DeepEqual(got, want) {
			t.Fatalf("ICS = %+v, want %+v", got, want)
		}
	})

	t.Run("same protocol merges and keeps other rule fields", func(t *testing.T) {
		m := iecPatchStore(iec)
		rec := patchRule(t, m, `{"description":"new","ics":{"ca":[1],"ioa":[{"start":2001,"end":2001}]}}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
		}
		r := m.cfg.Firewall.Rules[0]
		want := config.ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}, CA: []uint16{1}, IOA: []config.IOARange{{Start: 2001, End: 2001}}, Mode: "enforce"}
		if r.Description != "new" || r.Action != config.ActionAllow || !reflect.DeepEqual(r.ICS, want) {
			t.Fatalf("rule = %+v, want description new and ICS %+v", r, want)
		}
	})

	t.Run("patch without ics keeps the predicate", func(t *testing.T) {
		m := iecPatchStore(modbus)
		if rec := patchRule(t, m, `{"description":"new"}`); rec.Code != http.StatusOK {
			t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
		}
		if got := m.cfg.Firewall.Rules[0].ICS; !reflect.DeepEqual(got, modbus) {
			t.Fatalf("ICS = %+v, want %+v", got, modbus)
		}
	})

	rejects := []struct {
		name      string
		body      string
		want      string
		saveCalls int
	}{
		{"duplicate key inside ics", `{"ics":{"ca":[1],"ca":[2]}}`, `duplicate key \"ca\"`, 0},
		{"unknown key inside ics", `{"ics":{"typeIDs":[46]}}`, `unknown key \"typeIDs\"`, 0},
		{"writeOnly false on iec104", `{"ics":{"writeOnly":false}}`, "writeOnly is not supported", 0},
		{"validation runs after the merge", `{"ics":{"ca":[65535]}}`, "broadcast address", 1},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			m := iecPatchStore(iec)
			rec := patchRule(t, m, tc.body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("status %d body=%s, want 400 containing %q", rec.Code, rec.Body.String(), tc.want)
			}
			if m.calls != tc.saveCalls {
				t.Fatalf("store.Save calls = %d, want %d", m.calls, tc.saveCalls)
			}
		})
	}
}

func TestGenericICSSelectorClearReload(t *testing.T) {
	for _, ics := range []config.ICSPredicate{
		{Protocol: "modbus", FunctionCode: []uint8{3}, UnitID: new(uint8(0)), Addresses: []string{"0-10"}, Direction: "request"},
		{Protocol: "cip", FunctionCode: []uint8{14}, ObjectClasses: []uint16{4}, Direction: "request"},
	} {
		t.Run(ics.Protocol, func(t *testing.T) {
			store := iecPatchStore(ics)
			body := `{"ics":{"functionCode":null,"unitId":null,"addresses":null,"objectClasses":null}}`
			rec := patchRule(t, store, body)
			if rec.Code != http.StatusOK {
				t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
			}
			rec = httptest.NewRecorder()
			NewServer(store, nil).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/firewall/rules", nil))
			var rules []config.Rule
			if err := json.Unmarshal(rec.Body.Bytes(), &rules); err != nil {
				t.Fatal(err)
			}
			want := config.ICSPredicate{Protocol: ics.Protocol, Direction: "request"}
			if rec.Code != http.StatusOK || len(rules) != 1 || !reflect.DeepEqual(rules[0].ICS, want) {
				t.Fatalf("reloaded = %s", rec.Body.String())
			}
		})
	}
}

func TestICSRuleListAndDashboardUseAllPredicateFields(t *testing.T) {
	predicates := []config.ICSPredicate{
		{Protocol: "modbus"}, {ObjectClasses: []uint16{4}}, {Direction: "request"},
		{TypeIDs: []int{1}}, {Classes: []string{"monitor"}}, {CA: []uint16{0}},
		{IOA: []config.IOARange{{Start: 0, End: 0}}},
	}
	store := iecPatchStore(config.ICSPredicate{})
	store.cfg.Firewall.Rules = nil
	for i, p := range predicates {
		store.cfg.Firewall.Rules = append(store.cfg.Firewall.Rules, config.Rule{ID: string(rune('a' + i)), ICS: p, Action: config.ActionAllow})
	}
	store.cfg.Firewall.Rules = append(store.cfg.Firewall.Rules,
		config.Rule{ID: "plain", Action: config.ActionAllow},
		config.Rule{ID: "mode-only", Action: config.ActionAllow, ICS: config.ICSPredicate{Mode: "monitor"}})
	if got := countICSRules(store.cfg.Firewall.Rules); got != len(predicates) {
		t.Fatalf("dashboard ICS count = %d, want %d", got, len(predicates))
	}
	rec := httptest.NewRecorder()
	NewServer(store, nil).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/firewall/ics-rules", nil))
	var listed []config.Rule
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || len(listed) != len(predicates) {
		t.Fatalf("ICS list = %d %s", rec.Code, rec.Body.String())
	}
}
