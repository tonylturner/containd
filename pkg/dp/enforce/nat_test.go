// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"regexp"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestNATConfiguredZones(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		ingress string
		zones   map[string][]string
		sources []string
		egress  string
	}{
		{"custom", true, "outside", map[string][]string{"outside": {"eth0"}, "plant": {"eth1"}}, []string{"plant"}, "outside"},
		{"disabled", false, "outside", map[string][]string{"outside": {"eth0"}, "plant": {"eth1"}}, []string{"plant"}, "outside"},
		{"unbound", true, "outside", map[string][]string{"outside": {}, "plant": {"eth1"}}, []string{"plant"}, "outside"},
		{"missing", true, "outside", map[string][]string{"plant": {"eth1"}}, []string{"absent"}, "absent"},
		{"defaults", false, "outside", map[string][]string{"plant": {"eth1"}}, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := &rules.Snapshot{ZoneIfaces: tc.zones, NAT: rules.NATConfig{Enabled: true, EgressZone: tc.egress, SourceZones: tc.sources, PortForwards: []rules.PortForward{{ID: "forward", Enabled: tc.enabled, IngressZone: tc.ingress, Proto: "tcp", ListenPort: 443, DestIP: "192.0.2.10", DestPort: 8443}}}}
			text, err := NewCompiler().CompileFirewall(snap)
			if err != nil {
				t.Fatal(err)
			}
			assertDeclaredSets(t, text)
			if tc.name == "custom" {
				for _, want := range []string{"iifname @zone_plant_ifaces oifname @zone_outside_ifaces masquerade", "dnat ip to 192.0.2.10:8443", "iifname @zone_outside_ifaces ct status dnat tcp dport 8443 ip daddr 192.0.2.10 masquerade"} {
					if !strings.Contains(text, want) {
						t.Fatalf("missing %q:\n%s", want, text)
					}
				}
			} else if strings.Contains(text, "dnat") || strings.Contains(text, "192.0.2.10") {
				t.Fatalf("inactive forward emitted rules:\n%s", text)
			}
		})
	}
}

func assertDeclaredSets(t *testing.T, text string) {
	t.Helper()
	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*set\s+(\w+)\s*\{`).FindAllStringSubmatch(text, -1) {
		declared[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`@(\w+)`).FindAllStringSubmatch(text, -1) {
		if !declared[m[1]] {
			t.Errorf("undeclared set %s:\n%s", m[1], text)
		}
	}
}
