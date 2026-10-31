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
			{ID: "allow-modbus", Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}, ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "modbus", FunctionCode: []uint8{3}}, Action: rules.ActionAllow},
			{ID: "allow-https", Protocols: []rules.Protocol{{Name: "tcp", Port: "443"}}, Action: rules.ActionAllow},
		},
	}
}

// TestCompileFirewallActionsGolden pins named counter and meter objects;
// TestLoweringGoldens pins the complete ordered policy graph for this fixture.
func TestCompileFirewallActionsGolden(t *testing.T) {
	c := NewCompiler()
	c.QueueID = 100
	c.NFLogGroup = 7
	text, err := c.CompileFirewall(actionsSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	assertDeclaredSets(t, text)
	for _, want := range []string{actionsObjectsGolden} {
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
