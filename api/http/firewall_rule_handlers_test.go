// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

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
		{"null on a new field", `{"ics":{"typeIds":null}}`, "must not be null", 0},
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
