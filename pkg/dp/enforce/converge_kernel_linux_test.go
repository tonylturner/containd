// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// legacyTable is inet containd as containd 0.1.34 installed it: the whole
// policy, with forwarding dropped, and a flow block set without the
// protocol field.
const legacyTable = `table inet containd {
  set zone_lan_ifaces { type ifname; elements = { "cvg0" } }
  set block_hosts { type ipv4_addr; flags timeout; }
  set block_flows { type ipv4_addr . ipv4_addr . inet_service; flags timeout; }
  chain iec104_envelope { drop; }
  chain input { type filter hook input priority 0; policy drop; iifname "lo" accept; ct state { established, related } accept; }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ip saddr @block_hosts drop;
    meta l4proto { tcp, udp } ip saddr . ip daddr . th dport @block_flows drop;
    ct state { established, related } accept;
    tcp dport 2404 jump iec104_envelope;
  }
  chain prerouting { type nat hook prerouting priority dstnat; policy accept; }
  chain postrouting { type nat hook postrouting priority srcnat; policy accept; oifname @zone_lan_ifaces masquerade; }
}
add element inet containd block_flows { 198.18.90.2 . 198.18.100.2 . 18099 timeout 1h }
`

// TestKernelConvergesFromLegacyTable applies the current ruleset over a
// 0.1.34 inet containd. The legacy flow block survives as tcp and udp
// blocks and still drops, every stale chain and set is gone, the dynamic
// table has exactly the current layout, and forwarding follows the new
// policy. A second apply changes nothing in the dynamic table.
func TestKernelConvergesFromLegacyTable(t *testing.T) {
	lab := newNetnsLab(t, "cvg", 90, 30*time.Second)
	lab.run(t, "ip", "-n", lab.client, "route", "add", "198.18.100.0/24", "via", "198.18.90.1")
	lab.run(t, "ip", "-n", lab.target, "route", "add", "198.18.90.0/24", "via", "198.18.100.1")
	for _, port := range []int{18090, 18099} {
		lab.serveTarget(t, "198.18.100.2", port)
	}
	lab.nft(t, legacyTable)
	if err := lab.probe("198.18.100.2", 18090, "198.18.90.2"); err == nil {
		t.Fatal("the legacy policy does not drop forwarding")
	}

	c := NewCompiler()
	snap := &rules.Snapshot{Default: rules.ActionAllow}
	for _, pass := range []string{"converged", "reapplied"} {
		lab.apply(t, c, snap)
		if err := lab.probe("198.18.100.2", 18090, "198.18.90.2"); err != nil {
			t.Fatalf("%s: forwarding does not follow the new policy: %v", pass, err)
		}
		if err := lab.probe("198.18.100.2", 18099, "198.18.90.2"); err == nil {
			t.Fatalf("%s: the legacy flow block stopped dropping", pass)
		}
		set := lab.run(t, "nft", "list", "set", "inet", "containd", "block_flows")
		for _, proto := range []string{"tcp", "udp"} {
			if !strings.Contains(set, "198.18.90.2 . 198.18.100.2 . "+proto+" . 18099 timeout 59m") {
				t.Fatalf("%s: legacy flow block lost for %s:\n%s", pass, proto, set)
			}
		}
		live, err := NewNftApplier().ReadTable(lab.ctx, "containd")
		if err != nil {
			t.Fatal(err)
		}
		if script := c.InstallScript(live, "", ""); script != "" {
			t.Fatalf("%s: dynamic table is not the current layout; next install would run:\n%s", pass, script)
		}
		if len(live.Chains) != len(dynamicChains)+1 || len(live.Objects) != len(dynamicSets()) {
			t.Fatalf("%s: stale objects remain: %+v", pass, live)
		}
	}
}
