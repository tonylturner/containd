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
			var got []conduitResult
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			c := requireConduit(t, got, "lan", "wan")
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
			var got []conduitResult
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("status %d body=%s err=%v", rec.Code, rec.Body.String(), err)
			}
			if c := requireConduit(t, got, "lan", "wan"); c.State != "block" || !c.DefaultDeny {
				t.Fatalf("lan→wan state %q defaultDeny %v, want block true", c.State, c.DefaultDeny)
			}
		})
	}
}

func requireConduit(t *testing.T, conduits []conduitResult, from, to string) conduitResult {
	t.Helper()
	for _, c := range conduits {
		if c.From == from && c.To == to {
			return c
		}
	}
	t.Fatalf("missing conduit from %q to %q in %+v", from, to, conduits)
	return conduitResult{}
}

func TestSecurityConduitsStructuredIdentity(t *testing.T) {
	// The last zone also creates a collision in the retired joined-key format:
	// ("a→b", "a") and ("a", "b→a") must remain distinct.
	zones := []config.Zone{{Name: "a→b"}, {Name: "a"}, {Name: "b"}, {Name: "b→a"}}
	m := &mockStore{cfg: &config.Config{
		System: config.SystemConfig{Hostname: "containd"},
		Zones:  zones,
		Firewall: config.FirewallConfig{DefaultAction: config.ActionDeny, Rules: []config.Rule{{
			ID: "arrow-zone", SourceZones: []string{"a→b"}, DestZones: []string{"b"}, Action: config.ActionAllow,
		}}},
	}}
	for range 3 {
		rec := httptest.NewRecorder()
		NewServer(m, nil).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/security/conduits", nil))
		var got []conduitResult
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("status %d body=%s err=%v", rec.Code, rec.Body.String(), err)
		}
		if len(got) != len(zones)*(len(zones)-1) {
			t.Fatalf("got %d conduits: %s", len(got), rec.Body.String())
		}
		i := 0
		for _, from := range zones {
			for _, to := range zones {
				if from.Name == to.Name {
					continue
				}
				if got[i].From != from.Name || got[i].To != to.Name {
					t.Fatalf("conduit %d = (%q, %q), want (%q, %q)", i, got[i].From, got[i].To, from.Name, to.Name)
				}
				i++
			}
		}
		if c := requireConduit(t, got, "a→b", "b"); c.State != "allow" {
			t.Fatalf("arrow zone conduit = %+v", c)
		}
		if c := requireConduit(t, got, "a", "b"); c.State != "block" {
			t.Fatalf("plain zone conduit = %+v", c)
		}
	}
}

func TestSecurityConduitsEmptyArray(t *testing.T) {
	for _, zones := range [][]config.Zone{{}, {{Name: "alone"}}} {
		m := &mockStore{cfg: &config.Config{
			System: config.SystemConfig{Hostname: "containd"},
			Zones:  zones,
		}}
		rec := httptest.NewRecorder()
		NewServer(m, nil).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/security/conduits", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "[]" {
			t.Fatalf("status %d body=%s, want 200 []", rec.Code, rec.Body.String())
		}
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
