// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestSecurityConduitsDefaultAction(t *testing.T) {
	for _, tc := range []struct {
		stored      config.Action
		state       string
		defaultDeny bool
	}{
		{"", "block", true},
		{config.ActionDeny, "block", true},
		{config.ActionAllow, "unmodeled", false},
	} {
		t.Run(fmt.Sprintf("%q", tc.stored), func(t *testing.T) {
			m := &mockStore{cfg: &config.Config{
				System:   config.SystemConfig{Hostname: "containd"},
				Zones:    []config.Zone{{Name: "lan"}, {Name: "wan"}},
				Firewall: config.FirewallConfig{DefaultAction: tc.stored},
			}}
			rec := httptest.NewRecorder()
			NewServer(m, nil).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/security/conduits", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
			}
			var got map[string]conduitResult
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			c, ok := got["lan→wan"]
			if !ok {
				t.Fatalf("missing lan→wan conduit in %s", rec.Body.String())
			}
			if c.State != tc.state || c.DefaultDeny != tc.defaultDeny {
				t.Fatalf("state %q defaultDeny %v, want %q %v", c.State, c.DefaultDeny, tc.state, tc.defaultDeny)
			}
			if hasGap := slices.Contains(c.Gaps, "No default-deny policy"); hasGap == tc.defaultDeny {
				t.Fatalf("gaps %q with defaultDeny %v", c.Gaps, tc.defaultDeny)
			}
		})
	}
}

// A RESET rule refuses traffic like DENY: it blocks a conduit and, as a
// catch-all, counts as its default deny.
func TestSecurityConduitsResetIsDenial(t *testing.T) {
	for _, action := range []config.Action{config.ActionDeny, config.ActionReset} {
		t.Run(string(action), func(t *testing.T) {
			m := &mockStore{cfg: &config.Config{
				System: config.SystemConfig{Hostname: "containd"},
				Zones:  []config.Zone{{Name: "lan"}, {Name: "wan"}},
				Firewall: config.FirewallConfig{DefaultAction: config.ActionAllow, Rules: []config.Rule{
					{ID: "refuse-lan", SourceZones: []string{"lan"}, Action: action},
				}},
			}}
			rec := httptest.NewRecorder()
			NewServer(m, nil).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/security/conduits", nil))
			var got map[string]conduitResult
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("status %d body=%s err=%v", rec.Code, rec.Body.String(), err)
			}
			if c := got["lan→wan"]; c.State != "block" || !c.DefaultDeny {
				t.Fatalf("lan→wan state %q defaultDeny %v, want block true", c.State, c.DefaultDeny)
			}
		})
	}
}

func TestSecurityConduitsOrderedDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, state   string
		list          []config.Rule
		defaultAction config.Action
		protoCount    int
	}{
		{"deny first", "block", []config.Rule{{ID: "deny", Action: config.ActionDeny}, {ID: "allow", Action: config.ActionAllow, Protocols: []config.Protocol{{Name: "tcp", Port: "443"}}}}, config.ActionDeny, 0},
		{"reset first", "block", []config.Rule{{ID: "reset", Action: config.ActionReset}, {ID: "allow", Action: config.ActionAllow}}, config.ActionDeny, 0},
		{"allow first", "allow", []config.Rule{{ID: "allow", Action: config.ActionAllow}, {ID: "deny", Action: config.ActionDeny}}, config.ActionDeny, 0},
		{"service exception", "partial", []config.Rule{{ID: "allow", Action: config.ActionAllow, Protocols: []config.Protocol{{Name: "tcp", Port: "443"}}}, {ID: "deny", Action: config.ActionDeny}}, config.ActionDeny, 1},
		{"same service denied first", "block", []config.Rule{{ID: "deny", Action: config.ActionDeny, Protocols: []config.Protocol{{Name: "tcp", Port: "443"}}}, {ID: "allow", Action: config.ActionAllow, Protocols: []config.Protocol{{Name: "tcp", Port: "443"}}}}, config.ActionDeny, 0},
		{"conditional refusal", "partial", []config.Rule{{ID: "deny", Action: config.ActionDeny, Sources: []string{"192.0.2.0/24"}}, {ID: "allow", Action: config.ActionAllow}}, config.ActionAllow, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Firewall.Rules = tc.list
			cfg.Firewall.DefaultAction = tc.defaultAction
			got := buildConduitResult(cfg, computeConduitGlobals(cfg), "lan", "wan")
			if got.State != tc.state || len(got.Proto) != tc.protoCount {
				t.Fatalf("result=%+v", got)
			}
		})
	}
}
