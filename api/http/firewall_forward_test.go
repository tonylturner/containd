// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const publishForward = `{"id":"f","enabled":true,"ingressZone":"wan","proto":"tcp","listenPort":1502,"destIp":"10.0.0.2","destPort":502}`

func TestPublishPortForward(t *testing.T) {
	for _, tc := range []struct {
		name, reason, sources string
		ics, noAllow          bool
		rules                 int
		warning               bool
	}{
		{"no overlap", "generated", "", false, false, 2, false},
		{"inside", "inside", "", true, false, 2, false},
		{"partial", "partial", "192.0.2.0/24", true, false, 2, true},
		{"no allow", "", "", false, true, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.DataPlane.NFQueueGroup = 101
			cfg.Firewall.Rules = []config.Rule{{ID: "catchall", Action: config.ActionDeny}}
			if tc.ics {
				r := config.Rule{ID: "inspect", Action: config.ActionDeny, ICS: config.ICSPredicate{Protocol: "modbus", Mode: "enforce"}}
				if tc.sources != "" {
					r.Sources = []string{tc.sources}
				}
				cfg.Firewall.Rules = append([]config.Rule{r}, cfg.Firewall.Rules...)
			}
			store := &mockStore{cfg: cfg}
			body := `{"forward":` + publishForward
			if tc.noAllow {
				body += `,"allowRule":false`
			}
			rec := firewallRequest(store, "POST", "port-forwards", body+"}")
			var got struct {
				Forward   config.PortForward       `json:"forward"`
				Placement *config.ForwardPlacement `json:"placement"`
			}
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Forward.ID != "f" ||
				len(store.cfg.Firewall.Rules) != tc.rules || store.calls != 1 || len(store.cfg.Firewall.NAT.PortForwards) != 1 {
				t.Fatalf("response=%d %s calls=%d", rec.Code, rec.Body, store.calls)
			}
			if tc.noAllow {
				if got.Placement != nil || strings.Contains(rec.Body.String(), `"placement"`) {
					t.Fatal(rec.Body.String())
				}
				return
			}
			p := got.Placement
			if p == nil || p.Reason != tc.reason || (p.Warning != nil) != tc.warning {
				t.Fatalf("placement=%+v", p)
			}
			if tc.ics && (!reflect.DeepEqual(p.RuleIDs, []string{"inspect"}) || p.Rule != nil) {
				t.Fatalf("placement=%+v", p)
			}
			if !tc.ics && (p.Index != 0 || p.Rule == nil || store.cfg.Firewall.Rules[0].ViaForwards[0] != "f") {
				t.Fatalf("placement=%+v", p)
			}
			before := store.calls
			if rec := firewallRequest(store, "POST", "port-forwards", body+"}"); rec.Code != 400 || store.calls != before {
				t.Fatalf("duplicate=%d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestDeletePortForwardAndNATReplace(t *testing.T) {
	store := orderedStore()
	var f config.PortForward
	if err := json.Unmarshal([]byte(publishForward), &f); err != nil {
		t.Fatal(err)
	}
	g := f
	g.ID, g.ListenPort = "g", 2502
	store.cfg.Firewall.NAT.PortForwards = []config.PortForward{f, g}
	store.cfg.Firewall.Rules = []config.Rule{
		{ID: "allow", Action: config.ActionAllow, ViaForwards: []string{"f"}},
		{ID: "deny", Action: config.ActionDeny, ViaForwards: []string{"f"}},
		{ID: "reset", Action: config.ActionReset, ViaForwards: []string{"f"}},
		{ID: "edit", Action: config.ActionAllow, ViaForwards: []string{"f", "g"}},
		{ID: "unscoped", Action: config.ActionDeny},
	}
	rec := firewallRequest(store, "POST", "nat", `{"portForwards":[]}`)
	if rec.Code != 400 || len(store.cfg.Firewall.NAT.PortForwards) != 2 {
		t.Fatalf("dangling NAT replace=%d %s", rec.Code, rec.Body)
	}
	before := store.calls
	rec = firewallRequest(store, "DELETE", "port-forwards/f", "")
	var got struct {
		Deleted []string `json:"deletedRuleIds"`
		Edited  []string `json:"editedRuleIds"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil ||
		!reflect.DeepEqual(got.Deleted, []string{"allow", "deny", "reset"}) || !reflect.DeepEqual(got.Edited, []string{"edit"}) ||
		!reflect.DeepEqual(ruleIDs(store.cfg.Firewall.Rules), []string{"edit", "unscoped"}) ||
		!reflect.DeepEqual(store.cfg.Firewall.Rules[0].ViaForwards, []string{"g"}) || store.calls != before+1 {
		t.Fatalf("delete=%d %s rules=%+v", rec.Code, rec.Body, store.cfg.Firewall.Rules)
	}
	before = store.calls
	rec = firewallRequest(store, "DELETE", "port-forwards/f", "")
	if rec.Code != 404 || store.calls != before {
		t.Fatalf("unknown delete=%d %s", rec.Code, rec.Body)
	}
}

func TestPublishPortForwardValidationAtomic(t *testing.T) {
	store := orderedStore()
	rec := firewallRequest(store, "POST", "port-forwards", `{"forward":{"id":"bad","proto":"sctp"}}`)
	if rec.Code != 400 || len(store.cfg.Firewall.NAT.PortForwards) != 0 || len(store.cfg.Firewall.Rules) != 3 {
		t.Fatalf("invalid publish=%d %s", rec.Code, rec.Body)
	}
}
