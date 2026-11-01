// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func orderedStore() *mockStore {
	cfg := config.DefaultConfig()
	cfg.Firewall.Rules = []config.Rule{{ID: "a", Action: config.ActionDeny}, {ID: "b", Action: config.ActionAllow}, {ID: "c", Action: config.ActionReset}}
	return &mockStore{cfg: cfg}
}

func firewallRequest(store *mockStore, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := authedRequest(method, "/api/v1/firewall/"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	NewServer(store, nil).ServeHTTP(rec, withTestRevision(store, req))
	return rec
}

func ruleIDs(list []config.Rule) []string {
	out := []string{}
	for _, r := range list {
		out = append(out, r.ID)
	}
	return out
}

func TestFirewallRulePositions(t *testing.T) {
	for _, tc := range []struct {
		position string
		index    int
		order    []string
	}{
		{`"top"`, 0, []string{"new", "a", "b", "c"}},
		{`"bottom"`, 3, []string{"a", "b", "c", "new"}},
		{`{"before":"b"}`, 1, []string{"a", "new", "b", "c"}},
		{`{"after":"b"}`, 2, []string{"a", "b", "new", "c"}},
		{``, 3, []string{"a", "b", "c", "new"}},
	} {
		for _, endpoint := range []string{"rules", "ics-rules"} {
			t.Run(endpoint+"/"+tc.position, func(t *testing.T) {
				store := orderedStore()
				body := `{"id":"new","action":"ALLOW","ics":{"protocol":"modbus"}`
				if tc.position != "" {
					body += `,"position":` + tc.position
				}
				rec := firewallRequest(store, http.MethodPost, endpoint, body+"}")
				var got struct {
					ID    string `json:"id"`
					Index int    `json:"index"`
				}
				if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.ID != "new" || got.Index != tc.index ||
					!reflect.DeepEqual(ruleIDs(store.cfg.Firewall.Rules), tc.order) || store.calls != 1 {
					t.Fatalf("response=%d %s rules=%v calls=%d", rec.Code, rec.Body, ruleIDs(store.cfg.Firewall.Rules), store.calls)
				}
			})
		}
	}
}

func TestFirewallRuleMoveAndPatchSlot(t *testing.T) {
	for _, tc := range []struct {
		position string
		index    int
		order    []string
	}{
		{`"top"`, 0, []string{"b", "a", "c"}},
		{`"bottom"`, 2, []string{"a", "c", "b"}},
		{`{"before":"a"}`, 0, []string{"b", "a", "c"}},
		{`{"after":"c"}`, 2, []string{"a", "c", "b"}},
	} {
		t.Run(tc.position, func(t *testing.T) {
			store := orderedStore()
			rec := firewallRequest(store, "POST", "rules/b/move", `{"position":`+tc.position+`}`)
			var got struct {
				Index int           `json:"index"`
				Rules []config.Rule `json:"rules"`
			}
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Index != tc.index ||
				!reflect.DeepEqual(ruleIDs(got.Rules), tc.order) || store.calls != 1 {
				t.Fatalf("response=%d %s calls=%d", rec.Code, rec.Body, store.calls)
			}
			rec = firewallRequest(store, "PATCH", "rules/b", `{"description":"changed"}`)
			if rec.Code != 200 || !reflect.DeepEqual(ruleIDs(store.cfg.Firewall.Rules), tc.order) {
				t.Fatalf("patch moved rule: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestFirewallRulePositionErrorsAtomic(t *testing.T) {
	for _, position := range []string{`null`, `false`, `"middle"`, `{}`, `{"before":""}`, `{"before":"missing"}`, `{"before":"b","after":"a"}`, `{"before":"a","before":"c"}`} {
		t.Run(position, func(t *testing.T) {
			for _, path := range []string{"rules", "rules/b/move"} {
				store := orderedStore()
				body := `{"id":"new","action":"ALLOW","position":` + position + `}`
				if path != "rules" {
					body = `{"position":` + position + `}`
				}
				rec := firewallRequest(store, "POST", path, body)
				if rec.Code != 400 || store.calls != 0 || !reflect.DeepEqual(ruleIDs(store.cfg.Firewall.Rules), []string{"a", "b", "c"}) {
					t.Fatalf("%s: %d %s calls=%d", path, rec.Code, rec.Body, store.calls)
				}
			}
		})
	}
	for _, tc := range []struct {
		path, body string
		code       int
	}{
		{"rules/b/move", `{}`, 400},
		{"rules/b/move", `{"position":{"before":"b"}}`, 400},
		{"rules/b/move", `{"position":{"after":"b"}}`, 400},
		{"rules/missing/move", `{"position":"top"}`, 404},
		{"rules", `{"id":"new","id":"other","action":"ALLOW"}`, 400},
	} {
		store := orderedStore()
		rec := firewallRequest(store, "POST", tc.path, tc.body)
		if rec.Code != tc.code || store.calls != 0 {
			t.Fatalf("%s: %d %s", tc.body, rec.Code, rec.Body)
		}
	}
}
