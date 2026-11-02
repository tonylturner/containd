// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestSecurityConduitsMitreEvidenceLabels(t *testing.T) {
	servicePorts := []config.Protocol{
		{Name: "tcp", Port: "502"},
		{Name: "tcp", Port: "80"},
		{Name: "tcp", Port: "22"},
	}
	portHints := []string{
		"Heuristic (allowed service ports): T0886 Remote Services OT",
		"Heuristic (allowed service ports): T0843 Program Download",
		"Heuristic (allowed service ports): T1021 Remote Services",
	}
	for _, tc := range []struct {
		name      string
		from, to  string
		allow     bool
		protocols []config.Protocol
		ics       bool
		want      []string
	}{
		{name: "allowed service ports", from: "lan", to: "wan", allow: true, protocols: servicePorts, want: portHints},
		{name: "allowed service ports with ICS predicate", from: "lan", to: "wan", allow: true, protocols: servicePorts, ics: true, want: portHints},
		{
			name: "unrestricted policy", from: "lan", to: "wan", allow: true,
			want: []string{"Heuristic (policy state): T1048 Exfiltration Over Alt Protocol"},
		},
		{
			name: "source zone name", from: "wan", to: "lan",
			want: []string{
				"Heuristic (source zone name): T1190 Exploit Public App",
				"Heuristic (source zone name): T1595 Active Scanning",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Firewall.DefaultAction = config.ActionDeny
			cfg.Firewall.Rules = nil
			if tc.allow {
				rule := config.Rule{
					ID: "mitre-fixture", Action: config.ActionAllow,
					SourceZones: []string{tc.from}, DestZones: []string{tc.to},
					Protocols: tc.protocols,
				}
				if tc.ics {
					rule.ICS.Protocol = "modbus"
					rule.ICS.Mode = "enforce"
					cfg.DataPlane.NFQueueGroup = 101
				}
				cfg.Firewall.Rules = []config.Rule{rule}
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("invalid fixture: %v", err)
			}

			rec := httptest.NewRecorder()
			NewServer(&mockStore{cfg: cfg}, nil).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/security/conduits", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
			}
			var conduits []conduitResult
			if err := json.Unmarshal(rec.Body.Bytes(), &conduits); err != nil {
				t.Fatal(err)
			}
			if got := requireConduit(t, conduits, tc.from, tc.to).Mitre; !slices.Equal(got, tc.want) {
				t.Errorf("MITRE hints=%v want=%v", got, tc.want)
			}
			for _, conduit := range conduits {
				for _, hint := range conduit.Mitre {
					if !strings.HasPrefix(hint, "Heuristic (") {
						t.Errorf("%s→%s: missing evidence label: %q", conduit.From, conduit.To, hint)
					}
				}
			}
		})
	}
}
