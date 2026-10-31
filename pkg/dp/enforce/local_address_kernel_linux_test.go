// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"strings"
	"testing"
	"time"
)

// Both local addresses stay assigned throughout: only the device address-set
// elements change. New TCP connections must follow the current set in both
// the DNAT lookup and the post-DNAT original-destination admission predicate.
func TestKernelSpikeS5DNATOriginalDestinationSetUpdates(t *testing.T) {
	lab := newNetnsLab(t, "local", 41, 30*time.Second)
	lab.run(t, "ip", "addr", "add", "198.18.41.3/24", "dev", "local0")
	lab.run(t, "ip", "-n", lab.client, "route", "add", "default", "via", "198.18.41.1")
	lab.run(t, "ip", "-n", lab.target, "route", "add", "default", "via", "198.18.51.1")
	lab.serveTarget(t, "198.18.51.2", 18001)
	lab.nft(t, `table inet spike_local {
 set local4_local0 { type ipv4_addr; elements = { 198.18.41.1 }; }
 counter translated { }
 counter admitted { }
 chain pre { type nat hook prerouting priority dstnat; policy accept;
 iifname "local0" ip daddr @local4_local0 tcp dport 18000 counter name translated dnat ip to 198.18.51.2:18001
 }
 chain admission { type filter hook forward priority 0; policy drop;
 ct state established accept
 iifname "local0" ip daddr 198.18.51.2 tcp dport 18001 ct original ip daddr @local4_local0 counter name admitted accept
 }
}`)
	t.Cleanup(func() { lab.nft(t, "delete table inet spike_local") })
	if err := lab.probe("198.18.41.1", 18000, "198.18.41.2"); err != nil {
		t.Fatalf("initial local address: %v", err)
	}
	for _, addr := range []string{"198.18.41.3", "198.18.51.1"} {
		if err := lab.probe(addr, 18000, "198.18.41.2"); err == nil {
			t.Fatalf("nonmember local address %s unexpectedly translated", addr)
		}
	}
	// Only set-element operations: no replacement of a chain, hook or table.
	lab.nft(t, `delete element inet spike_local local4_local0 { 198.18.41.1 }
add element inet spike_local local4_local0 { 198.18.41.3 }`)
	if err := lab.probe("198.18.41.3", 18000, "198.18.41.2"); err != nil {
		t.Fatalf("new local address after element update: %v", err)
	}
	if err := lab.probe("198.18.41.1", 18000, "198.18.41.2"); err == nil {
		t.Fatal("removed local address still translated new connections")
	}
	// The original destination is not the translated backend; direct routing
	// to that same backend cannot inherit the forward's permission.
	if err := lab.probe("198.18.51.2", 18001, "198.18.41.2"); err == nil {
		t.Fatal("direct backend connection inherited the DNAT permission")
	}
	for _, name := range []string{"translated", "admitted"} {
		out := lab.run(t, "nft", "list", "counter", "inet", "spike_local", name)
		if !strings.Contains(out, "packets 2 ") {
			t.Fatalf("%s expected two successful new connections: %s", name, out)
		}
		t.Log(out)
	}
}
