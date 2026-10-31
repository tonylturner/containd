// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestNATKernelCustomZoneReturnPath(t *testing.T) {
	lab := newNetnsLab(t, "nat", 10, 30*time.Second)
	// The target deliberately has no default route: a successful response proves
	// scoped masquerade supplies the return path, regardless of its zone name.
	lab.serveTarget(t, "198.18.20.2", 18001)
	for _, pair := range [][2]string{{"outside", "plant"}, {"edge", "workshop"}, {"wan", "dmz"}} {
		t.Run(pair[0]+"_to_"+pair[1], func(t *testing.T) {
			snap := &rules.Snapshot{Default: rules.ActionDeny, ZoneIfaces: map[string][]string{pair[0]: {"nat0"}, pair[1]: {"nat1"}}, NAT: rules.NATConfig{Enabled: true, EgressZone: pair[0], SourceZones: []string{pair[1]}, PortForwards: []rules.PortForward{{ID: "probe", Enabled: true, IngressZone: pair[0], Proto: "tcp", ListenPort: 18000, DestIP: "198.18.20.2", DestPort: 18001, AllowedSources: []string{"198.18.10.2/32"}}}}}
			snap.ForwardMatches = map[string]rules.ForwardMatch{"probe": {Enabled: true, IngressDevices: []string{"nat0"}, Protocol: "tcp", ListenPort: 18000, Backend: netip.MustParseAddrPort("198.18.20.2:18001"), AllowedSources: []netip.Prefix{netip.MustParsePrefix("198.18.10.2/32")}}}
			snap.LocalIPv4ByDevice = map[string][]netip.Addr{"nat0": {netip.MustParseAddr("198.18.10.1")}}
			snap.Firewall = []rules.Entry{{ID: "via-probe", ViaForwards: []string{"probe"}, Action: rules.ActionAllow}}

			lab.apply(t, NewCompiler(), snap)
			if err := lab.probe("198.18.10.1", 18000, "198.18.20.1"); err != nil {
				t.Fatal(err)
			}
			snap.NAT.PortForwards[0].Enabled = false
			snap.ForwardMatches = nil
			lab.apply(t, NewCompiler(), snap)
			if err := lab.probe("198.18.10.1", 18000, "198.18.20.1"); err == nil {
				t.Fatal("disabled forward still reachable")
			}
			if listing := lab.run(t, "nft", "list", "ruleset"); strings.Contains(listing, "dnat") {
				t.Fatalf("disabled DNAT survived: %s", listing)
			}
		})
	}
}
