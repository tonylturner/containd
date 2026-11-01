// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func assertText(t *testing.T, text string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestOrderedTransportPairs(t *testing.T) {
	for _, q := range []int{0, 100} {
		for _, a := range []rules.Action{rules.ActionAllow, rules.ActionDeny, rules.ActionReset} {
			for _, b := range []rules.Action{rules.ActionAllow, rules.ActionDeny, rules.ActionReset} {
				for _, icsA := range []bool{false, true} {
					for _, icsB := range []bool{false, true} {
						t.Run(fmt.Sprint(q, a, b, icsA, icsB), func(t *testing.T) {
							snap := &rules.Snapshot{Firewall: []rules.Entry{{ID: "z", Action: a}, {ID: "a", Action: b}}}
							for i, ics := range []bool{icsA, icsB} {
								if ics {
									snap.Firewall[i].ICS = rules.ICSPredicate{Protocol: "modbus", Mode: "enforce", FunctionCode: []uint8{6}}
								}
							}
							c := NewCompiler()
							c.QueueID = q
							text, err := c.CompileFirewall(snap)
							if err != nil {
								t.Fatal(err)
							}
							body := strings.Join(chainBody(t, text, "ordered_s2"), "\n")
							first := strings.Index(body, "goto ordered_s2_rule_0")
							second := strings.Index(body, "goto ordered_s2_rule_1")
							if first < 0 || second < 0 {
								t.Fatalf("terminal chains are unreachable:\n%s", body)
							}
							if first >= second {
								t.Fatal("configured order lost")
							}
							for i, e := range snap.Firewall {
								name := fmt.Sprintf("ordered_s2_rule_%d", i)
								terminal := strings.Join(chainBody(t, text, name), "\n")
								if q > 0 && isDPIEligible(e) {
									assertText(t, terminal, "goto admit_unconditional")
									if strings.Contains(terminal, "counter") {
										t.Fatal("S2 duplicated an inspection counter")
									}
								} else if e.Action == rules.ActionAllow {
									assertText(t, terminal, nonAdmitGuard+" goto deny_clean", "ct mark & 0x00000006 != 0x00000002", "goto admit_unconditional")
								} else if e.Action == rules.ActionReset {
									assertText(t, terminal, "goto reset_tcp_clean", "goto reset_other_clean")
								} else {
									assertText(t, terminal, "goto deny_clean")
								}
							}
						})
					}
				}
			}
		}
	}
}

func TestAdmissionTailAndMasks(t *testing.T) {
	for _, parity := range []uint32{0, markabi.ParityBit} {
		for _, def := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
			c := gateCompiler()
			snap := gateSnapshot()
			snap.AdmissionParity, snap.Default = parity, def
			text, err := c.CompileFirewall(snap)
			if err != nil {
				t.Fatal(err)
			}
			for _, base := range []string{"forward", GateInputChain, GateReplyChain} {
				body := strings.Join(chainBody(t, text, base), "\n")
				assertText(t, body, fmt.Sprintf("ct state established ct mark & 0x00000007 == 0x%08x goto admit_clean", markabi.AdmittedBit|parity))
				if strings.Index(body, nonAdmitGuard) > strings.Index(body, "ct state established jump") ||
					strings.Index(body, "ct state established jump") > strings.Index(body, "goto admit_clean") {
					t.Fatal("continuation or conditional dispatch follows parity")
				}
			}
			for _, exit := range []string{"admit_clean", "related_clean"} {
				assertText(t, strings.Join(chainBody(t, text, exit), "\n"), nonAdmitGuard+" goto deny_clean", "meta mark set meta mark & 0xe0ffffff", "accept")
			}
			assertText(t, strings.Join(chainBody(t, text, "admit_unconditional"), "\n"),
				fmt.Sprintf("%s ct mark set (ct mark & 0xfffffff9) | 0x%08x", trackedState, markabi.AdmittedBit|parity))
			assertText(t, strings.Join(chainBody(t, text, "admit_conditional"), "\n"), trackedState+" ct mark set ct mark & 0xfffffffd")
			last := chainBody(t, text, "ordered_s2")
			want := "goto deny_clean"
			if def == rules.ActionAllow {
				want = "goto admit_unconditional"
			}
			if last[len(last)-1] != want {
				t.Fatalf("default = %s", last[len(last)-1])
			}
		}
	}
	if _, err := NewCompiler().CompileFirewall(&rules.Snapshot{AdmissionParity: 1}); err == nil {
		t.Fatal("invalid parity accepted")
	}
}

func TestInspectionPriorityAndOnceOnlyEffects(t *testing.T) {
	snap := &rules.Snapshot{Firewall: []rules.Entry{
		{ID: "first-allow", Action: rules.ActionAllow},
		{ID: "monitor-generic", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor"}},
		{ID: "monitor-iec", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"}},
		{ID: "enforce-generic", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"}},
		{ID: "enforce-iec-z", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
		{ID: "enforce-iec-a", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
		{ID: "meter", Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 10}},
		{ID: "tag", Action: rules.ActionTag},
	}}
	c := NewCompiler()
	c.QueueID = 100
	text, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	lines := chainBody(t, text, "forward")
	var owners []string
	for _, l := range lines {
		if strings.Contains(l, "limit rate") {
			assertText(t, l, unobservedGuard)
		}
		if strings.Contains(l, " jump ") && strings.Contains(l, "counter name") {
			assertText(t, l, unobservedGuard)
			for _, id := range []string{"enforce-iec-z", "enforce-iec-a", "enforce-generic", "monitor-iec", "monitor-generic"} {
				if strings.Contains(l, counterStmt(id)) && (len(owners) == 0 || owners[len(owners)-1] != id) {
					owners = append(owners, id)
				}
			}
		}
		if strings.Contains(l, counterStmt("tag")) {
			assertText(t, l, "ct state != established")
		}
	}
	if !reflect.DeepEqual(owners, []string{"enforce-iec-z", "enforce-iec-a", "enforce-generic", "monitor-iec", "monitor-generic"}) {
		t.Fatalf("steering order %v", owners)
	}
}

func forwardSnapshot() *rules.Snapshot {
	return &rules.Snapshot{
		Default: rules.ActionDeny,
		ForwardMatches: map[string]rules.ForwardMatch{"f": {
			Enabled: true, IngressDevices: []string{"wan0", "wan.1"}, Protocol: "tcp",
			ListenPort: 1502, Backend: netip.MustParseAddrPort("10.0.0.8:502"),
			AllowedSources: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		}},
		LocalIPv4ByDevice: map[string][]netip.Addr{"wan0": {netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("203.0.113.3")}},
		ZoneIfaces:        map[string][]string{"wan": {"wan0", "wan.1"}, "lan": {"lan0"}},
		NAT:               rules.NATConfig{Enabled: true},
		Firewall:          []rules.Entry{{ID: "via", ViaForwards: []string{"f"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}, Action: rules.ActionAllow}},
	}
}

func packetPolicySnapshot() *rules.Snapshot {
	snap := forwardSnapshot()
	snap.AdmissionParity = markabi.ParityBit
	snap.IdentityBindings = []rules.IdentityBinding{
		{IP: "198.51.100.5", Identities: []string{"ops"}},
		{IP: "2001:db8::5", Identities: []string{"ops"}},
	}
	snap.Firewall = append([]rules.Entry{
		{ID: "deny-telnet", Action: rules.ActionDeny, Protocols: []rules.Protocol{{Name: "tcp", Port: "23"}}},
		{ID: "monitor-iec", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"}},
		{ID: "inspected-deny", Action: rules.ActionDeny, Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
			ICS:        rules.ICSPredicate{Protocol: "modbus", Mode: "enforce", FunctionCode: []uint8{6}},
			Identities: []string{"ops"}, Schedule: maintenanceWindow, ViaForwards: []string{"f"}},
		{ID: "enforce-iec", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
		{ID: "meter-via", Action: rules.ActionRateLimit, ViaForwards: []string{"f"}, RateLimit: &rules.RateLimit{PacketsPerSecond: 100}},
		{ID: "tag", Action: rules.ActionTag, SourceZones: []string{"lan"}},
	}, snap.Firewall...)
	return snap
}

func TestForwardLoweringAndLocalAddressUpdate(t *testing.T) {
	snap := forwardSnapshot()
	c := NewCompiler()
	text, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	assertDeclaredSets(t, text)
	assertText(t, text, "elements = { 203.0.113.2, 203.0.113.3 }", "ct mark set ct mark | 0x00000001 dnat ip to 10.0.0.8:502",
		"ct direction reply meta l4proto tcp ct reply proto-src 502 oifname \"wan0\"", "ct original proto-dst 1502", "ct original ip daddr @local4_77616e30",
		"ct original ip saddr { 198.51.100.0/24 }", "ct reply ip saddr 10.0.0.8 ct reply proto-src 502")
	if strings.Contains(text, "ct status dnat") {
		t.Fatal("foreign DNAT accepted")
	}
	viaDispatches := 0
	for _, l := range chainBody(t, text, "ordered_s2") {
		if strings.Contains(l, "goto ordered_s2_rule_0") {
			viaDispatches++
			assertText(t, l, trackedState, "ct mark & 0x00000001 != 0")
		}
	}
	// Two ingress devices, each with original and reply alternatives.
	if viaDispatches != 4 {
		t.Fatalf("via dispatches = %d, want 4", viaDispatches)
	}
	masq, err := gateMasqueradeLines(snap, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range forwardMatchClauses(snap.ForwardMatches["f"], targetGateInput) {
		assertText(t, text, match+" masquerade")
		assertText(t, strings.Join(masq, "\n"), match+" "+ctMarkSet(GateMasqSelCtMark))
	}
	update, err := c.LocalAddressUpdate("wan0", nil)
	if err != nil || update != "flush set inet containd_policy local4_77616e30\n" {
		t.Fatalf("empty update = %q, %v", update, err)
	}
	update, err = c.LocalAddressUpdate("wan0", snap.LocalIPv4ByDevice["wan0"])
	if err != nil {
		t.Fatal(err)
	}
	assertText(t, update, "add element inet containd_policy local4_77616e30 { 203.0.113.2, 203.0.113.3 }")
	for _, addr := range []netip.Addr{{}, netip.MustParseAddr("::1"), netip.MustParseAddr("::ffff:192.0.2.1")} {
		if _, err := c.LocalAddressUpdate("wan0", []netip.Addr{addr}); err == nil {
			t.Fatal("non IPv4 address accepted")
		}
	}
	if _, err := c.LocalAddressUpdate(`bad"`, nil); err == nil {
		t.Fatal("invalid device accepted")
	}
	snap.Firewall[0].ViaForwards = []string{"missing"}
	warnings := c.RuleWarnings(snap)
	if len(warnings) != 1 || warnings[0].Predicate != PredicateForward {
		t.Fatalf("forward warnings %v", warnings)
	}
	snap.Firewall[0].ViaForwards = []string{"f"}
	snap.Firewall[0].SourceZones = []string{"lan"}
	if warnings := c.RuleWarnings(snap); len(warnings) != 1 || warnings[0].Predicate != PredicateForward {
		t.Fatalf("disjoint ingress zones not diagnosed: %v", warnings)
	}
}

func TestUntrackedAdmissionAndMonitorDefault(t *testing.T) {
	snap := forwardSnapshot()
	snap.Firewall = append(snap.Firewall,
		rules.Entry{ID: "plain", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}})
	text, err := NewCompiler().CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	untrackedDispatches := 0
	for _, line := range chainBody(t, text, "ordered_s2") {
		if strings.Contains(line, untrackedState) {
			untrackedDispatches++
			assertText(t, line, "tcp dport 502 goto ordered_s2_rule_1")
			if strings.Contains(line, "ct mark") || strings.Contains(line, "ct original") || strings.Contains(line, "ct reply") {
				t.Fatal("untrusted tuple fabricated conntrack evidence")
			}
		}
	}
	if untrackedDispatches != 1 {
		t.Fatalf("untracked dispatches = %d, want 1", untrackedDispatches)
	}
	snap.Firewall = []rules.Entry{{ID: "monitor", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor"}}}
	for _, q := range []int{0, 100} {
		c := NewCompiler()
		c.QueueID = q
		text, err := c.CompileFirewall(snap)
		if err != nil {
			t.Fatal(err)
		}
		if got := chainBody(t, text, "ordered_s2"); !reflect.DeepEqual(got, []string{"goto deny_clean"}) {
			t.Fatalf("monitor granted admission: %v", got)
		}
	}
}

func TestExplicitForwardAndInactiveReferences(t *testing.T) {
	for _, active := range []bool{false, true} {
		snap := forwardSnapshot()
		f := snap.ForwardMatches["f"]
		f.Enabled, f.ListenAddress = active, netip.MustParseAddr("203.0.113.99")
		snap.ForwardMatches["f"] = f
		snap.NAT.Enabled = false // publication does not depend on source NAT
		text, err := NewCompiler().CompileFirewall(snap)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(text, "dnat ip to") != active {
			t.Fatal("inactive forward translated or NAT.Enabled disabled publication")
		}
		if active {
			assertText(t, text, "ip daddr 203.0.113.99", "tcp dport 1502", "ct original ip daddr 203.0.113.99")
			if strings.Contains(strings.Join(chainBody(t, text, "prerouting"), "\n"), "@local4") {
				t.Fatal("explicit listener depended on dynamic local addresses")
			}
		} else {
			if got := chainBody(t, text, "ordered_s2"); !reflect.DeepEqual(got, []string{"goto deny_clean"}) {
				t.Fatalf("disabled reference matched: %v", got)
			}
		}
	}
}

func TestInspectionScheduleAdmissionHorizon(t *testing.T) {
	from := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour) // no maintenance window in this horizon
	for _, queue := range []int{0, 100} {
		entry := rules.Entry{ID: "scheduled-deny", Action: rules.ActionDeny,
			Schedule: maintenanceWindow, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"}}
		p, err := newPredicates(&rules.Snapshot{Firewall: []rules.Entry{entry}}, queue)
		if err != nil {
			t.Fatal(err)
		}
		set, err := p.scheduleSet(entry)
		if err != nil {
			t.Fatal(err)
		}
		elems, err := set.elements(from, to)
		if err != nil {
			t.Fatal(err)
		}
		// With inspection the rule is a transport admission, so an
		// exhausted planner must not turn it into an always-on grant.
		if got := parseIntervals(t, elems).contain(to.Add(time.Minute)); got != (queue == 0) {
			t.Fatalf("queue=%d: exhausted transport predicate holds %v", queue, got)
		}
	}
}

func TestViaExcludesIPv6IdentityAndAddressLines(t *testing.T) {
	snap := packetPolicySnapshot()
	c := goldenCompiler()
	text, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	assertDeclaredSets(t, text)
	for _, line := range chainBody(t, text, "ordered_s2") {
		if strings.Contains(line, "ct mark & 0x00000001") && strings.Contains(line, "ip6") {
			t.Fatalf("IPv4 publication mixed with IPv6 evidence: %s", line)
		}
	}
	snap.Firewall = []rules.Entry{{ID: "v6-via", Action: rules.ActionAllow, ViaForwards: []string{"f"}, Sources: []string{"2001:db8::/32"}}}
	text, err = c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	if got := chainBody(t, text, "ordered_s2"); !reflect.DeepEqual(got, []string{"goto deny_clean"}) {
		t.Fatalf("IPv6 publication matched: %v", got)
	}
}
