// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
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
	for i, pair := range [][2]string{{"outside", "plant"}, {"edge", "workshop"}, {"wan", "dmz"}} {
		t.Run(pair[0]+"_to_"+pair[1], func(t *testing.T) {
			snap := &rules.Snapshot{Default: rules.ActionDeny, ZoneIfaces: map[string][]string{pair[0]: {"nat0"}, pair[1]: {"nat1"}}, NAT: rules.NATConfig{Enabled: true, EgressZone: pair[0], SourceZones: []string{pair[1]}, PortForwards: []rules.PortForward{{ID: "probe", Enabled: true, IngressZone: pair[0], Proto: "tcp", ListenPort: 18000, DestIP: "198.18.20.2", DestPort: 18001, AllowedSources: []string{"198.18.10.2/32"}}}}}
			snap.ForwardMatches = map[string]rules.ForwardMatch{"probe": {Enabled: true, IngressDevices: []string{"nat0"}, Protocol: "tcp", ListenPort: 18000, Backend: netip.MustParseAddrPort("198.18.20.2:18001"), AllowedSources: []netip.Prefix{netip.MustParsePrefix("198.18.10.2/32")}}}
			snap.LocalIPv4ByDevice = map[string][]netip.Addr{"nat0": {netip.MustParseAddr("198.18.10.1")}}
			snap.Firewall = []rules.Entry{{ID: "via-probe", ViaForwards: []string{"probe"}, Action: rules.ActionAllow}}

			lab.apply(t, NewCompiler(), snap)
			probeNATFresh(t, lab, 41000+i*3, true)

			// Withdraw only permission. The publication and its resolver remain
			// enabled, and a new tuple must still translate without being admitted.
			permission := snap.Firewall
			snap.Firewall = nil
			lab.apply(t, NewCompiler(), snap)
			before := natTranslationPackets(t, lab)
			probeNATFresh(t, lab, 41001+i*3, false)
			if after := natTranslationPackets(t, lab); after <= before {
				t.Fatalf("denied fresh flow did not translate: DNAT packets %d -> %d", before, after)
			}
			snap.Firewall = permission
			lab.apply(t, NewCompiler(), snap)
			probeNATFresh(t, lab, 41002+i*3, true)

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

// Explicit source ports keep every phase independent of prior admitted
// conntrack entries, including across the custom-zone subtests.
func probeNATFresh(t *testing.T, lab *netnsLab, sourcePort int, delivered bool) {
	t.Helper()
	wantDelivery := "False"
	if delivered {
		wantDelivery = "True"
	}
	script := fmt.Sprintf(`import socket
s=socket.socket(); s.settimeout(1); s.bind(("198.18.10.2",%d))
try:
 s.connect(("198.18.10.1",18000))
except (TimeoutError, ConnectionRefusedError):
 assert %s == False, "permitted flow failed"
else:
 assert %s == True, "translate-only flow was admitted"
 assert s.recv(64)==b"198.18.20.1", "scoped return-path masquerade missing"
`, sourcePort, wantDelivery, wantDelivery)
	out, err := exec.CommandContext(lab.ctx, "ip", "netns", "exec", lab.client, "python3", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("fresh NAT probe from port %d (delivery=%t): %v: %s", sourcePort, delivered, err, out)
	}
}

func natTranslationPackets(t *testing.T, lab *netnsLab) uint64 {
	t.Helper()
	var listing struct {
		Nftables []struct {
			Rule struct {
				Expr []struct {
					DNAT    json.RawMessage `json:"dnat"`
					Counter *struct {
						Packets uint64 `json:"packets"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(lab.run(t, "nft", "-j", "list", "chain", "inet", "containd_policy", "prerouting")), &listing); err != nil {
		t.Fatal(err)
	}
	var packets uint64
	found := 0
	for _, item := range listing.Nftables {
		var counter *uint64
		dnat := false
		for _, expr := range item.Rule.Expr {
			dnat = dnat || len(expr.DNAT) != 0
			if expr.Counter != nil {
				counter = &expr.Counter.Packets
			}
		}
		if dnat {
			if counter == nil {
				t.Fatal("DNAT rule has no translation counter")
			}
			found++
			packets += *counter
		}
	}
	if found != 1 {
		t.Fatalf("DNAT rules = %d, want 1", found)
	}
	return packets
}
