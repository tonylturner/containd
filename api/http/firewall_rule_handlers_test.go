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
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
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

func previewRule(t *testing.T, events []dpevents.Event, rule string) previewRuleResponse {
	t.Helper()
	eng := newRuntimeMockEngine()
	eng.eventsResp = events
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/firewall/rules/preview", bytes.NewBufferString(rule))
	req.Header.Set("Content-Type", "application/json")
	NewServerWithEngine(&mockStore{}, nil, eng).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status %d body=%s", rec.Code, rec.Body.String())
	}
	var resp previewRuleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	return resp
}

func iecEvent(id uint64, kind string, request bool, attrs map[string]any) dpevents.Event {
	ev := dpevents.Event{ID: id, Proto: "iec104", Kind: kind, Transport: "tcp", Attributes: attrs,
		SrcIP: "10.60.60.10", DstIP: "10.30.30.30", SrcPort: 40000, DstPort: 2404}
	if !request {
		ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort = ev.DstIP, ev.SrcIP, ev.DstPort, ev.SrcPort
	}
	return ev
}

// Attribute values are float64, as they arrive from the engine's JSON.
func TestPreviewFirewallRuleIEC104(t *testing.T) {
	events := []dpevents.Event{
		iecEvent(1, "request", true, map[string]any{"apci_type": "I", "direction": "request", "class": "control", "type_id": float64(46), "ca": float64(1), "ioa": float64(2001)}),
		iecEvent(2, "request", true, map[string]any{"apci_type": "I", "direction": "request", "class": "control", "type_id": float64(46), "ca": float64(2), "ioa": float64(2001)}),
		iecEvent(3, "response", false, map[string]any{"apci_type": "I", "direction": "response", "class": "control", "type_id": float64(46), "ca": float64(1), "ioa": float64(2001)}),
		iecEvent(4, "ics.decision", true, map[string]any{"decision": "allow", "type_id": float64(46), "ca": float64(1), "ioa": float64(2001), "direction": "request"}),
		iecEvent(5, "request", true, map[string]any{"apci_type": "I", "direction": "request", "class": "control", "type_id": float64(46), "ca": float64(65535), "ioa": float64(2001)}),
		{ID: 6, Proto: "modbus", Kind: "request", Transport: "tcp", SrcIP: "10.60.60.10", DstIP: "10.30.30.30", DstPort: 2404,
			Attributes: map[string]any{"function_code": float64(46)}},
	}
	command := `{"id":"cmd","sources":["10.60.60.10/32"],"destinations":["10.30.30.30/32"],
		"protocols":[{"name":"tcp","port":"2404"}],"action":"ALLOW",
		"ics":{"protocol":"iec104","typeIds":[46],"classes":["control"],"ca":[1],"ioa":[{"start":2001,"end":2001}],"mode":"enforce"}}`
	resp := previewRule(t, events, command)
	if resp.MatchCount != 2 || resp.SampleMatches[0].ID != 1 || resp.SampleMatches[1].ID != 3 {
		t.Fatalf("command rule matched %d events %+v; want events 1 and 3", resp.MatchCount, resp.SampleMatches)
	}

	// The response half matches in the session orientation: source = the
	// client, port = 2404.
	confirm := `{"id":"confirm","sources":["10.60.60.10/32"],"protocols":[{"name":"tcp","port":"2404"}],"action":"ALLOW",
		"ics":{"protocol":"iec104","classes":["control"],"direction":"response"}}`
	resp = previewRule(t, events, confirm)
	if resp.MatchCount != 1 || resp.SampleMatches[0].ID != 3 {
		t.Fatalf("confirm rule matched %d events %+v; want event 3", resp.MatchCount, resp.SampleMatches)
	}

	// A broadcast object (event 5) never matches an ALLOW but can match a
	// DENY; decision events (4) and other protocols (6) never count.
	allow := `{"id":"allow","action":"ALLOW","ics":{"protocol":"iec104","typeIds":[46]}}`
	if resp = previewRule(t, events, allow); resp.MatchCount != 3 {
		t.Fatalf("allow rule matched %d events %+v; want events 1-3", resp.MatchCount, resp.SampleMatches)
	}
	deny := `{"id":"deny","action":"DENY","ics":{"protocol":"iec104","typeIds":[46]}}`
	if resp = previewRule(t, events, deny); resp.MatchCount != 4 || resp.SampleMatches[3].ID != 5 {
		t.Fatalf("deny rule matched %d events %+v; want events 1-3 and 5", resp.MatchCount, resp.SampleMatches)
	}
}
