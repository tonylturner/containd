// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// actionsSnapshot has one rule of every action, in no particular order.
func actionsSnapshot() *rules.Snapshot {
	return &rules.Snapshot{
		Default:    rules.ActionDeny,
		ZoneIfaces: map[string][]string{"it": {"eth1"}, "ot": {"eth2"}},
		Firewall: []rules.Entry{
			{ID: "deny-ot", DestZones: []string{"ot"}, Action: rules.ActionDeny},
			{ID: "reset-telnet", Protocols: []rules.Protocol{{Name: "tcp", Port: "23"}, {Name: "udp", Port: "69"}}, Action: rules.ActionReset, Log: true},
			{ID: "reset-it", SourceZones: []string{"it"}, DestZones: []string{"ot"}, Action: rules.ActionReset},
			{ID: "police-dns", Protocols: []rules.Protocol{{Name: "udp", Port: "53"}}, Action: rules.ActionRateLimit,
				RateLimit: &rules.RateLimit{PacketsPerSecond: 100, Burst: 20}, Log: true},
			{ID: "police-ot", DestZones: []string{"ot"}, Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 1000, Burst: 50000}},
			{ID: "police-plc", Destinations: []string{"10.0.2.10/32"}, Protocols: []rules.Protocol{{Name: "icmp"}}, Action: rules.ActionRateLimit,
				RateLimit: &rules.RateLimit{PacketsPerSecond: 5, Burst: 5}},
			{ID: "tag-plc", Destinations: []string{"10.0.2.0/24"}, Action: rules.ActionTag, Tag: "plc"},
			{ID: "allow-modbus", Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}, ICS: rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}}, Action: rules.ActionAllow},
			{ID: "allow-https", Protocols: []rules.Protocol{{Name: "tcp", Port: "443"}}, Action: rules.ActionAllow},
		},
	}
}

// TestCompileFirewallActionsGolden pins the lowering of every action and
// the forward chain's order: RATE_LIMIT meters before NFQUEUE and the
// established accept, then TAG counting lines, every ALLOW, and the DENY
// and RESET rules by rule ID. Every line counts into its rule's counter.
func TestCompileFirewallActionsGolden(t *testing.T) {
	c := NewCompiler()
	c.QueueID = 100
	c.NFLogGroup = 7
	text, err := c.CompileFirewall(actionsSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	assertDeclaredSets(t, text)
	for _, want := range []string{actionsObjectsGolden, actionsForwardGolden} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing:\n%s\nin:\n%s", want, text)
		}
	}
}

const actionsObjectsGolden = `  counter rule_8d37a5ef81b19a2c { }
  counter rule_0fcbbe08bd166a2d { }
  counter rule_1e73e60a8a2f5234 { }
  counter rule_7a3e0b308833ca56 { }
  counter rule_7a3e0b308833ca56_excess { }
  set rule_7a3e0b308833ca56_m4p {
    type ipv4_addr . ipv4_addr . inet_proto . inet_service . inet_service;
    size 65536;
    flags dynamic,timeout;
    timeout 10s;
  }
  set rule_7a3e0b308833ca56_m6p {
    type ipv6_addr . ipv6_addr . inet_proto . inet_service . inet_service;
    size 65536;
    flags dynamic,timeout;
    timeout 10s;
  }
  counter rule_c6679320c12984e0 { }
  counter rule_c6679320c12984e0_excess { }
  set rule_c6679320c12984e0_m4 {
    type ipv4_addr . ipv4_addr . inet_proto;
    size 65536;
    flags dynamic,timeout;
    timeout 50s;
  }
  set rule_c6679320c12984e0_m4p {
    type ipv4_addr . ipv4_addr . inet_proto . inet_service . inet_service;
    size 65536;
    flags dynamic,timeout;
    timeout 50s;
  }
  set rule_c6679320c12984e0_m6 {
    type ipv6_addr . ipv6_addr . inet_proto;
    size 65536;
    flags dynamic,timeout;
    timeout 50s;
  }
  set rule_c6679320c12984e0_m6p {
    type ipv6_addr . ipv6_addr . inet_proto . inet_service . inet_service;
    size 65536;
    flags dynamic,timeout;
    timeout 50s;
  }
  counter rule_344d02b85c20d34e { }
  counter rule_344d02b85c20d34e_excess { }
  set rule_344d02b85c20d34e_m4 {
    type ipv4_addr . ipv4_addr . inet_proto;
    size 65536;
    flags dynamic,timeout;
    timeout 10s;
  }
  counter rule_d70a03c1af306977 { }
  counter rule_e2b88688266c1ba6 { }
  counter rule_8df01028adf79ed2 { }
`

const actionsForwardGolden = `  chain forward {
    type filter hook forward priority 0;
    policy drop;
    meta nfproto ipv4 ct state { invalid, untracked } udp dport 53 counter name "rule_7a3e0b308833ca56" update @rule_7a3e0b308833ca56_m4p { ip saddr . ip daddr . meta l4proto . th sport . th dport limit rate over 100/second burst 20 packets } counter name "rule_7a3e0b308833ca56_excess" log prefix "containd:police-dns:RATE_LIMIT " group 7 drop;
    meta nfproto ipv4 ct state != { invalid, untracked } meta l4proto udp ct reply proto-src 53 counter name "rule_7a3e0b308833ca56" update @rule_7a3e0b308833ca56_m4p { ip saddr . ip daddr . meta l4proto . th sport . th dport limit rate over 100/second burst 20 packets } counter name "rule_7a3e0b308833ca56_excess" log prefix "containd:police-dns:RATE_LIMIT " group 7 drop;
    meta nfproto ipv6 ct state { invalid, untracked } udp dport 53 counter name "rule_7a3e0b308833ca56" update @rule_7a3e0b308833ca56_m6p { ip6 saddr . ip6 daddr . meta l4proto . th sport . th dport limit rate over 100/second burst 20 packets } counter name "rule_7a3e0b308833ca56_excess" log prefix "containd:police-dns:RATE_LIMIT " group 7 drop;
    meta nfproto ipv6 ct state != { invalid, untracked } meta l4proto udp ct reply proto-src 53 counter name "rule_7a3e0b308833ca56" update @rule_7a3e0b308833ca56_m6p { ip6 saddr . ip6 daddr . meta l4proto . th sport . th dport limit rate over 100/second burst 20 packets } counter name "rule_7a3e0b308833ca56_excess" log prefix "containd:police-dns:RATE_LIMIT " group 7 drop;
    meta nfproto ipv4 meta l4proto { tcp, udp } ct state { invalid, untracked } oifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m4p { ip saddr . ip daddr . meta l4proto . th sport . th dport limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv4 meta l4proto { tcp, udp } ct state != { invalid, untracked } ct direction original oifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m4p { ip saddr . ip daddr . meta l4proto . th sport . th dport limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv4 meta l4proto { tcp, udp } ct state != { invalid, untracked } ct direction reply iifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m4p { ip saddr . ip daddr . meta l4proto . th sport . th dport limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv4 meta l4proto != { tcp, udp } ct state { invalid, untracked } oifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m4 { ip saddr . ip daddr . meta l4proto limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv4 meta l4proto != { tcp, udp } ct state != { invalid, untracked } ct direction original oifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m4 { ip saddr . ip daddr . meta l4proto limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv4 meta l4proto != { tcp, udp } ct state != { invalid, untracked } ct direction reply iifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m4 { ip saddr . ip daddr . meta l4proto limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv6 meta l4proto { tcp, udp } ct state { invalid, untracked } oifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m6p { ip6 saddr . ip6 daddr . meta l4proto . th sport . th dport limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv6 meta l4proto { tcp, udp } ct state != { invalid, untracked } ct direction original oifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m6p { ip6 saddr . ip6 daddr . meta l4proto . th sport . th dport limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv6 meta l4proto { tcp, udp } ct state != { invalid, untracked } ct direction reply iifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m6p { ip6 saddr . ip6 daddr . meta l4proto . th sport . th dport limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv6 meta l4proto != { tcp, udp } ct state { invalid, untracked } oifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m6 { ip6 saddr . ip6 daddr . meta l4proto limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv6 meta l4proto != { tcp, udp } ct state != { invalid, untracked } ct direction original oifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m6 { ip6 saddr . ip6 daddr . meta l4proto limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv6 meta l4proto != { tcp, udp } ct state != { invalid, untracked } ct direction reply iifname { "eth2" } counter name "rule_c6679320c12984e0" update @rule_c6679320c12984e0_m6 { ip6 saddr . ip6 daddr . meta l4proto limit rate over 1000/second burst 50000 packets } counter name "rule_c6679320c12984e0_excess" drop;
    meta nfproto ipv4 ct state { invalid, untracked } meta l4proto icmp ip daddr { 10.0.2.10/32 } counter name "rule_344d02b85c20d34e" update @rule_344d02b85c20d34e_m4 { ip saddr . ip daddr . meta l4proto limit rate over 5/second burst 5 packets } counter name "rule_344d02b85c20d34e_excess" drop;
    meta nfproto ipv4 ct state != { invalid, untracked } meta l4proto icmp ct reply ip saddr { 10.0.2.10/32 } counter name "rule_344d02b85c20d34e" update @rule_344d02b85c20d34e_m4 { ip saddr . ip daddr . meta l4proto limit rate over 5/second burst 5 packets } counter name "rule_344d02b85c20d34e_excess" drop;
    tcp dport 502 counter name "rule_e2b88688266c1ba6" jump ics_queue;
    ct state { established, related } accept;
    ip daddr { 10.0.2.0/24 } counter name "rule_d70a03c1af306977";
    tcp dport 443 counter name "rule_8df01028adf79ed2" accept;
    oifname { "eth2" } counter name "rule_8d37a5ef81b19a2c" drop;
    meta l4proto tcp iifname { "eth1" } oifname { "eth2" } counter name "rule_1e73e60a8a2f5234" reject with tcp reset;
    iifname { "eth1" } oifname { "eth2" } counter name "rule_1e73e60a8a2f5234" reject with icmpx admin-prohibited;
    tcp dport 23 counter name "rule_0fcbbe08bd166a2d" log prefix "containd:reset-telnet:RESET " group 7 reject with tcp reset;
    udp dport 69 counter name "rule_0fcbbe08bd166a2d" log prefix "containd:reset-telnet:RESET " group 7 reject with icmpx admin-prohibited;
  }
`
