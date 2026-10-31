// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"regexp"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// gateSnapshot has every kind of forward decision a gated connection can
// meet (zone pair, addresses, port, port forward grant, IEC104 and generic
// ICS queues, meter, TAG, conditional identity, default deny), source NAT
// with a port forward, and a selection with two egress zones, exclusions
// and ICS endpoints.
func gateSnapshot() *rules.Snapshot {
	return &rules.Snapshot{
		Default:          rules.ActionDeny,
		ZoneIfaces:       map[string][]string{"it": {"eth1"}, "ot": {"eth2"}, "wan": {"eth0"}, "dmz": {"eth3"}},
		IdentityBindings: []rules.IdentityBinding{{IP: "10.1.0.5", Identities: []string{"ops"}}},
		Firewall: []rules.Entry{
			{ID: "web-it-ot", SourceZones: []string{"it"}, DestZones: []string{"ot"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "80"}}, Action: rules.ActionAllow},
			{ID: "cidr-any", Sources: []string{"10.1.0.0/24"}, Destinations: []string{"10.2.0.0/24"}, Action: rules.ActionAllow},
			{ID: "wan-out", SourceZones: []string{"it", "dmz"}, DestZones: []string{"wan"}, Action: rules.ActionAllow, Log: true},
			{ID: "deny-dmz", DestZones: []string{"dmz"}, Action: rules.ActionDeny},
			{ID: "reset-telnet", Protocols: []rules.Protocol{{Name: "tcp", Port: "23"}}, Action: rules.ActionReset},
			{ID: "police", SourceZones: []string{"it"}, DestZones: []string{"ot"}, Protocols: []rules.Protocol{{Name: "tcp"}}, Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 100}},
			{ID: "tag-lab", SourceZones: []string{"it"}, Action: rules.ActionTag, Tag: "lab"},
			{ID: "ops-web", Identities: []string{"ops"}, DestZones: []string{"ot"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "8080"}}, Action: rules.ActionAllow},
			{ID: "iec", SourceZones: []string{"it"}, DestZones: []string{"ot"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}}, ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "iec104"}, Action: rules.ActionAllow},
			{ID: "modbus", SourceZones: []string{"it"}, DestZones: []string{"ot"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}, ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "modbus"}, Action: rules.ActionAllow},
		},
		NAT: rules.NATConfig{Enabled: true, EgressZone: "wan", SourceZones: []string{"it", "dmz"},
			PortForwards: []rules.PortForward{{ID: "pf-web", Enabled: true, IngressZone: "wan", Proto: "tcp", ListenPort: 8080, DestIP: "10.2.0.10", DestPort: 80}}},
		Gate: rules.GateSelection{
			Enabled: true,
			Zones:   []rules.GateZone{{Name: "ot", Index: 1, Devices: []string{"eth2"}}, {Name: "wan", Index: 2, Devices: []string{"eth0"}}},
			Include: []rules.GateEntry{
				{SourceDevices: []string{"eth1"}, DestZones: []string{"ot", "wan"}, Ports: []rules.GatePortRange{{Lo: 80, Hi: 80}, {Lo: 8000, Hi: 8099}}},
				{DestZones: []string{"ot"}, Ports: []rules.GatePortRange{{Lo: 8080, Hi: 8080}}},
			},
			Exclude: []rules.GateEntry{
				{Family: 4, Destinations: []string{"10.2.0.99/32"}},
				{SourceDevices: []string{"eth3"}, DestDevices: []string{"eth2"}, Ports: []rules.GatePortRange{{Lo: 80, Hi: 80}}},
				{Family: 6, Sources: []string{"2001:db8:1::/64"}},
			},
			ICSDevices:   []string{"eth3"},
			ICSCIDRs:     []string{"10.2.0.50/32", "2001:db8:2::50/128"},
			FailPolicy:   "closed",
			DownloadMode: "hold",
		},
	}
}

// gateCompiler compiles gateSnapshot with the default listener ports, a
// queue and logging, in the refusing admission state.
func gateCompiler() *Compiler {
	c := NewCompiler()
	c.QueueID, c.NFLogGroup = 100, 7
	c.GatePlainPort, c.GateMasqPort = DefaultGatePlainPort, DefaultGateMasqPort
	return c
}

// chainBody returns the rule lines of chain in a compiled policy table,
// without the chain's type and policy lines.
func chainBody(t *testing.T, script, chain string) []string {
	t.Helper()
	start := strings.Index(script, "  chain "+chain+" {\n")
	if start < 0 {
		t.Fatalf("no chain %s in:\n%s", chain, script)
	}
	body := script[start+len("  chain "+chain+" {\n"):]
	body = body[:strings.Index(body, "  }\n")]
	var out []string
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		line = strings.TrimSuffix(strings.TrimSpace(line), ";")
		if line == "" || strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "policy ") {
			continue
		}
		out = append(out, line)
	}
	return out
}

var oifnameSet = regexp.MustCompile(`oifname \{ ("eth\d"(?:, "eth\d")*) \}`)

// gateZoneIndices maps each device of gateSnapshot's gate zones to the
// clause that matches its zone's index.
func gateZoneIndices() map[string]string {
	return map[string]string{
		`"eth2"`:         gateZoneClause([]uint8{1}),
		`"eth0"`:         gateZoneClause([]uint8{2}),
		`"eth0", "eth2"`: gateZoneClause([]uint8{1, 2}),
	}
}

// egressFromMark rewrites the forward chain's lines for the gate's input
// target: a line with an egress zone outside the selection (no index) is
// dropped, every other egress set becomes its index clause.
func egressFromMark(t *testing.T, lines []string) []string {
	t.Helper()
	var out []string
	for _, line := range lines {
		m := oifnameSet.FindStringSubmatch(line)
		if m == nil {
			out = append(out, line)
			continue
		}
		clause, ok := gateZoneIndices()[m[1]]
		if !ok {
			continue
		}
		out = append(out, strings.Replace(line, m[0], clause, 1))
	}
	return out
}

// TestGateInputDecidesLikeForward: the gate's input chain is the forward
// chain with the gate guard, IEC104 steering (never gated) and the
// untracked meter lines (never gated) left out, egress zones read from the
// connection mark on original-direction lines, reply-direction lines left
// out, and the default made explicit.
func TestGateInputDecidesLikeForward(t *testing.T) {
	script, err := gateCompiler().CompileFirewall(gateSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, line := range chainBody(t, script, "forward")[1:] {
		switch {
		case strings.Contains(line, "jump "+IEC104EnvelopeChain), strings.Contains(line, untrackedState), strings.Contains(line, "ct direction reply"):
			continue
		}
		want = append(want, strings.Replace(line, "jump "+conditionalScopeChain, "jump "+GateInputChain+"_scope", 1))
	}
	want = append(egressFromMark(t, want), "drop")
	got := chainBody(t, script, GateInputChain)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("gate_in:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if forward := chainBody(t, script, "forward"); forward[0] != gateForwardGuard {
		t.Fatalf("forward starts with %q, want the gate guard", forward[0])
	}
	for _, kind := range []string{"counter name", "log prefix", "jump " + ICSQueueChain, "ct status dnat"} {
		if !strings.Contains(strings.Join(got, "\n"), kind) {
			t.Fatalf("gate_in carries no %q line", kind)
		}
	}
}

// TestGateRecheckAndReplyMirrorForward: the recheck chains of the gate
// targets are the forward recheck with egress from the mark, one direction
// each; the reply chain passes resets, then is the meters' reply lines, the
// recheck jump and accept.
func TestGateRecheckAndReplyMirrorForward(t *testing.T) {
	script, err := gateCompiler().CompileFirewall(gateSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	direction := func(lines []string, keep string) []string {
		var out []string
		for _, l := range lines {
			if !strings.Contains(l, "ct direction") || strings.Contains(l, keep) {
				out = append(out, l)
			}
		}
		return out
	}
	for _, c := range []struct {
		name, direction string
		rewrite         func(*testing.T, []string) []string
	}{{GateInputChain, "ct direction original", egressFromMark}, {GateReplyChain, "ct direction reply", replyIngressFromMark}} {
		for _, suffix := range []string{"_scope", "_policy"} {
			want := direction(chainBody(t, script, "conditional"+suffix), c.direction)
			for i := range want {
				want[i] = strings.Replace(want[i], "goto "+conditionalPolicyChain, "goto "+c.name+"_policy", 1)
			}
			want = c.rewrite(t, want)
			if got := chainBody(t, script, c.name+suffix); strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("%s%s:\n%s\nwant:\n%s", c.name, suffix, strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		}
	}
	want := []string{"tcp flags & rst == rst accept"}
	for _, line := range chainBody(t, script, "forward") {
		if strings.Contains(line, "ct direction reply") && strings.Contains(line, "limit rate") {
			want = append(want, line)
		}
	}
	want = append(replyIngressFromMark(t, want), "ct state established jump "+GateReplyChain+"_scope", "accept")
	if got := chainBody(t, script, GateReplyChain); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%s:\n%s\nwant:\n%s", GateReplyChain, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

var iifnameSet = regexp.MustCompile(`ct direction reply iifname \{ ("eth\d"(?:, "eth\d")*) \}`)

// replyIngressFromMark rewrites reply-direction lines: the ingress set, the
// original egress, becomes the index clause.
func replyIngressFromMark(t *testing.T, lines []string) []string {
	t.Helper()
	var out []string
	for _, line := range lines {
		m := iifnameSet.FindStringSubmatch(line)
		if m == nil {
			out = append(out, line)
			continue
		}
		clause, ok := gateZoneIndices()[m[1]]
		if !ok {
			continue
		}
		out = append(out, strings.Replace(line, m[0], "ct direction reply "+clause, 1))
	}
	return out
}

// TestGateAdmitStatesAndSwitch: the admission chain is written in the
// compiler's state and the switch script rewrites it alone.
func TestGateAdmitStatesAndSwitch(t *testing.T) {
	want := map[GateAdmitState][]string{
		GateAdmitRefuse: {"jump " + gateICSChain, "ct mark & 0x00100000 == 0x00100000 reject with tcp reset"},
		GateAdmitOpen:   {"jump " + GateDeliverChain},
		GateAdmitPass:   {"ct mark set ct mark & 0xffed00ff return"},
	}
	for state, rules := range want {
		c := gateCompiler()
		c.GateAdmit = state
		script, err := c.CompileFirewall(gateSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		if got := chainBody(t, script, GateAdmitChain); strings.Join(got, "\n") != strings.Join(rules, "\n") {
			t.Fatalf("state %d: gate_admit = %q, want %q", state, got, rules)
		}
		switchScript := "flush chain inet containd_policy gate_admit\n"
		for _, r := range rules {
			switchScript += "add rule inet containd_policy gate_admit " + r + "\n"
		}
		if got := c.GateAdmitSwitch(state); got != switchScript {
			t.Fatalf("state %d: switch = %q, want %q", state, got, switchScript)
		}
	}
	if got := gateAdmitRules(GateAdmitState(9)); strings.Join(got, "\n") != strings.Join(want[GateAdmitRefuse], "\n") {
		t.Fatalf("unknown state admits: %q", got)
	}
}

// TestGateDeliveryOutlivesSelection: a ruleset without a selection keeps
// every delivery chain, so gated connections survive a selection change,
// and selects nothing; without listener ports there is no gate at all.
func TestGateDeliveryOutlivesSelection(t *testing.T) {
	snap := gateSnapshot()
	snap.Gate = rules.GateSelection{}
	script, err := gateCompiler().CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	assertDeclaredSets(t, script)
	for _, chain := range []string{GatePreChain, GateDeliverChain, GateAdmitChain, gateICSChain, GateInputChain, GateReplyChain, GateOutputMarkChain, "output"} {
		if !strings.Contains(script, "  chain "+chain+" {\n") {
			t.Fatalf("chain %s missing without a selection:\n%s", chain, script)
		}
	}
	if strings.Contains(script, gateSelectChain) {
		t.Fatalf("selection chain present without a selection:\n%s", script)
	}
	pre := chainBody(t, script, GatePreChain)
	wantPre := []string{
		`iifname "lo" return`,
		"ct mark & 0x00200000 == 0x00200000 ct direction reply meta mark set meta mark | 0x00400000 accept",
		"fib daddr type local return",
		"ct mark & 0x00100000 == 0x00100000 jump " + GateDeliverChain,
		"ct mark & 0x00100000 == 0x00100000 reject with tcp reset",
	}
	if strings.Join(pre, "\n") != strings.Join(wantPre, "\n") {
		t.Fatalf("gate_pre without selection:\n%s", strings.Join(pre, "\n"))
	}
	if body := chainBody(t, script, gateICSChain); len(body) != 0 {
		t.Fatalf("ICS chain without a selection: %q", body)
	}
	for _, want := range []string{
		"add rule inet containd input ct mark & 0x00100000 == 0x00100000 ip saddr @block_hosts drop\n",
		"add rule inet containd output meta mark & 0x00800000 == 0x00800000 meta l4proto { tcp, udp } ip saddr . ip daddr . meta l4proto . th dport @block_flows drop\n",
		"    meta mark & 0x00810000 == 0x00810000 masquerade;\n",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in:\n%s", want, script)
		}
	}

	plain, err := NewCompiler().CompileFirewall(gateSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"gate_", "ct mark", "tproxy", "chain output", "0x00800000"} {
		if strings.Contains(plain, token) {
			t.Fatalf("ruleset without listener ports mentions %q:\n%s", token, plain)
		}
	}
}

// TestGateListenerPortsValidated: the ports come as a distinct pair or not
// at all, and NewCompilerWithSettings carries them.
func TestGateListenerPortsValidated(t *testing.T) {
	for name, ports := range map[string][2]uint16{"plain only": {18100, 0}, "masq only": {0, 18101}, "same": {18100, 18100}} {
		c := NewCompiler()
		c.GatePlainPort, c.GateMasqPort = ports[0], ports[1]
		if _, err := c.CompileFirewall(gateSnapshot()); err == nil {
			t.Fatalf("%s: compiled", name)
		}
	}
	c := NewCompilerWithSettings(CompilerSettings{GatePlainPort: 1, GateMasqPort: 2}, nil)
	if c.GatePlainPort != 1 || c.GateMasqPort != 2 || !c.SteersGate() {
		t.Fatalf("settings not carried: %+v", c)
	}
	if NewCompiler().SteersGate() {
		t.Fatal("a compiler without ports steers the gate")
	}
}

// TestGateSelectionRefusesMalformedEntries: entries the control plane
// never produces fail the compile instead of selecting the wrong thing.
func TestGateSelectionRefusesMalformedEntries(t *testing.T) {
	for name, mutate := range map[string]func(g *rules.GateSelection){
		"exclude without constraints":  func(g *rules.GateSelection) { g.Exclude = []rules.GateEntry{{}} },
		"include without ports":        func(g *rules.GateSelection) { g.Include[0].Ports = nil },
		"include with addresses":       func(g *rules.GateSelection) { g.Include[0].Family, g.Include[0].Sources = 4, []string{"10.0.0.0/8"} },
		"include of an unindexed zone": func(g *rules.GateSelection) { g.Include[0].DestZones = []string{"dmz"} },
		"address without family":       func(g *rules.GateSelection) { g.Exclude[0].Family = 0 },
		"address of the other family":  func(g *rules.GateSelection) { g.Exclude[0].Destinations = []string{"2001:db8::1/128"} },
		"bad address":                  func(g *rules.GateSelection) { g.Exclude[0].Destinations = []string{"10.0.0.0/8 }; accept"} },
		"bad device":                   func(g *rules.GateSelection) { g.ICSDevices = []string{`eth0"`} },
		"reversed port range":          func(g *rules.GateSelection) { g.Include[0].Ports = []rules.GatePortRange{{Lo: 90, Hi: 80}} },
	} {
		snap := gateSnapshot()
		mutate(&snap.Gate)
		if _, err := gateCompiler().CompileFirewall(snap); err == nil {
			t.Fatalf("%s: compiled", name)
		}
	}
}
