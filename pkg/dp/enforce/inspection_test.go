// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Assert the emitted steering, not just ctLines: inspection must select replies
// before even an established connection can reuse transport admission.
func TestGenericInspectionBothDirections(t *testing.T) {
	for _, protocol := range []struct{ name, port string }{
		{"modbus", "502"}, {"dnp3", "20000"}, {"cip", "44818"},
	} {
		for _, mode := range []string{"enforce", "monitor"} {
			for _, layout := range []string{"unrestricted", "zones", "snat", "dnat", "via"} {
				t.Run(fmt.Sprintf("%s/%s/%s", protocol.name, mode, layout), func(t *testing.T) {
					snap := forwardSnapshot()
					entry := rules.Entry{
						ID: "inspect", Action: rules.ActionDeny,
						Protocols: []rules.Protocol{{Name: "tcp", Port: protocol.port}},
						ICS:       rules.ICSPredicate{Protocol: protocol.name, Mode: mode, Direction: "response"},
						// Neither predicate may hide the transport scope.
						Identities: []string{"ops"}, Schedule: maintenanceWindow,
					}
					if layout != "unrestricted" {
						entry.SourceZones, entry.DestZones = []string{"wan"}, []string{"lan"}
					}
					if layout == "snat" || layout == "dnat" || layout == "via" {
						entry.Sources, entry.Destinations = []string{"198.51.100.5"}, []string{"10.0.0.8"}
					}
					if layout == "snat" {
						snap.NAT.EgressZone, snap.NAT.SourceZones = "lan", []string{"wan"}
					}
					if layout == "via" {
						entry.ViaForwards = []string{"f"}
					}
					// The publication uses a different front-side port.
					f := snap.ForwardMatches["f"]
					f.Backend = netip.MustParseAddrPort("10.0.0.8:" + protocol.port)
					snap.ForwardMatches["f"] = f
					snap.Firewall = []rules.Entry{{ID: "earlier-allow", Action: rules.ActionAllow}, entry}
					c := NewCompiler()
					c.QueueID = 100
					text, err := c.CompileFirewall(snap)
					if err != nil {
						t.Fatal(err)
					}
					queue := enforceQueueChain
					if mode == "monitor" {
						queue = ICSQueueChain
					}
					lines := chainBody(t, text, "forward")
					var tracked []string
					for i, line := range lines {
						if !strings.Contains(line, "jump "+queue) {
							continue
						}
						assertText(t, line, unobservedGuard, counterStmt(entry.ID))
						if strings.Contains(line, "meta time") || strings.Contains(line, "identity_") {
							t.Fatalf("steering depends on current admission predicates: %s", line)
						}
						for j, later := range lines {
							if strings.Contains(later, "goto admit_clean") ||
								strings.Contains(later, "goto ordered_s2") ||
								strings.Contains(later, "jump "+conditionalScopeChain) {
								if i >= j {
									t.Fatalf("inspection follows admission: %s / %s", line, later)
								}
							}
						}
						if strings.Contains(line, trackedState) {
							tracked = append(tracked, line)
							assertText(t, line, "ct reply proto-src "+protocol.port)
						}
					}
					switch layout {
					case "unrestricted":
						if len(tracked) != 1 || strings.Contains(tracked[0], "ct direction") {
							t.Fatalf("unrestricted scope must cover both directions: %v", tracked)
						}
					default:
						want := 2
						if layout == "via" {
							want = 4 // two ingress devices, both directions
						}
						if len(tracked) != want {
							t.Fatalf("steering alternatives = %d, want %d: %v", len(tracked), want, tracked)
						}
						original, reply := 0, 0
						for _, line := range tracked {
							if strings.Count(line, "ct direction ") != 1 {
								t.Fatalf("ambiguous direction: %s", line)
							}
							if strings.Contains(line, "ct direction reply") {
								reply++
								assertText(t, line, `iifname { "lan0" } oifname { "wan.1", "wan0" }`)
								if layout == "via" {
									assertText(t, line, "ct original proto-dst 1502", "ct original ip daddr @local4_", `oifname "wan`)
								}
							} else {
								original++
								assertText(t, line, `ct direction original iifname { "wan.1", "wan0" } oifname { "lan0" }`)
							}
							if layout == "snat" || layout == "dnat" || layout == "via" {
								assertText(t, line, "ct original ip saddr { 198.51.100.5 }", "ct reply ip saddr { 10.0.0.8 }")
								if strings.Contains(line, "ct reply ip daddr") {
									t.Fatalf("SNAT address substituted for original client: %s", line)
								}
							}
						}
						if original != want/2 || reply != want/2 {
							t.Fatalf("original/reply alternatives = %d/%d", original, reply)
						}
					}
				})
			}
		}
	}
}
