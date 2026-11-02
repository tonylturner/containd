// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestSecurityConduitsProtocolWhitelistAllGrants(t *testing.T) {
	https := config.Rule{
		ID: "https", Action: config.ActionAllow, SourceZones: []string{"lan"}, DestZones: []string{"wan"},
		Protocols: []config.Protocol{{Name: "tcp", Port: "443"}},
	}
	host := config.Rule{
		ID: "host", Action: config.ActionAllow, SourceZones: []string{"lan"}, DestZones: []string{"wan"},
		Sources: []string{"192.0.2.1/32"},
	}
	hostHTTPS := host
	hostHTTPS.Protocols = https.Protocols
	conditionalDeny := host
	conditionalDeny.Action = config.ActionDeny
	otherZone := host
	otherZone.SourceZones = []string{"wan"}
	monitor := host
	monitor.ICS.Protocol, monitor.ICS.Mode = "modbus", "monitor"
	enforce := monitor
	enforce.ICS.Mode = "enforce"
	for _, tc := range []struct {
		name     string
		rules    []config.Rule
		fallback config.Action
		want     bool
	}{
		{"restricted grant", []config.Rule{https}, config.ActionDeny, true},
		{"restricted conditional grants", []config.Rule{hostHTTPS, https}, config.ActionDeny, true},
		{"unrestricted host first", []config.Rule{host, https}, config.ActionDeny, false},
		{"unrestricted host last", []config.Rule{https, host}, config.ActionDeny, false},
		{"conditional refusal and ALLOW fallback", []config.Rule{conditionalDeny, https}, config.ActionAllow, false},
		{"ALLOW fallback", []config.Rule{https}, config.ActionAllow, false},
		{"no grants", nil, config.ActionDeny, false},
		{"other conduit grant", []config.Rule{otherZone, https}, config.ActionDeny, true},
		{"monitor is not a grant", []config.Rule{monitor, https}, config.ActionDeny, true},
		{"monitor only", []config.Rule{monitor}, config.ActionDeny, false},
		{"ICS-only grant is not transport proof", []config.Rule{enforce, https}, config.ActionDeny, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.DataPlane.NFQueueGroup = 101
			cfg.Firewall.DefaultAction, cfg.Firewall.Rules = tc.fallback, tc.rules
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			NewServer(&mockStore{cfg: cfg}, nil).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/security/conduits", nil))
			var conduits []conduitResult
			if err := json.Unmarshal(rec.Body.Bytes(), &conduits); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("status %d body=%s err=%v", rec.Code, rec.Body, err)
			}
			got := requireConduit(t, conduits, "lan", "wan")
			provenance := "unknown"
			if tc.want {
				provenance = "configured"
			}
			evidence := got.Checks["protoWhitelist"]
			if got.ProtoWhitelist != tc.want || evidence.Provenance != provenance || evidence.Reason == "" {
				t.Fatalf("whitelist=%v evidence=%+v; want %v, %s with reason", got.ProtoWhitelist, evidence, tc.want, provenance)
			}
		})
	}
}
