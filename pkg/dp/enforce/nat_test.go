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

// assertDeclaredSets requires every @set reference to name a set declared in
// the same table, inside a table block or by an add set command.
func assertDeclaredSets(t *testing.T, text string) {
	t.Helper()
	tableBlock := regexp.MustCompile(`^table inet (\w+) \{$`)
	setInBlock := regexp.MustCompile(`^\s+set (\w+) \{$`)
	command := regexp.MustCompile(`^add (set|rule) inet (\w+) (\w+)`)
	ref := regexp.MustCompile(`@(\w+)`)
	declared := map[string]bool{}
	type use struct{ table, set string }
	var uses []use
	block := ""
	for _, line := range strings.Split(text, "\n") {
		table := block
		if m := tableBlock.FindStringSubmatch(line); m != nil {
			block = m[1]
			continue
		}
		if line == "}" {
			block = ""
			continue
		}
		if m := command.FindStringSubmatch(line); m != nil {
			table = m[2]
			if m[1] == "set" {
				declared[table+" "+m[3]] = true
			}
		} else if m := setInBlock.FindStringSubmatch(line); m != nil && block != "" {
			declared[block+" "+m[1]] = true
		}
		for _, m := range ref.FindAllStringSubmatch(line, -1) {
			uses = append(uses, use{table, m[1]})
		}
	}
	for _, u := range uses {
		if !declared[u.table+" "+u.set] {
			t.Errorf("undeclared set %s in table %q:\n%s", u.set, u.table, text)
		}
	}
}
