// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package enforce

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func iecSnapshot() *rules.Snapshot {
	return &rules.Snapshot{
		Default:    rules.ActionDeny,
		ZoneIfaces: map[string][]string{"lan4": {"eth1"}, "station": {"eth2"}},
		Firewall: []rules.Entry{
			{
				ID: "b-broad-2404", Action: rules.ActionAllow,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}},
			},
			{
				ID: "a-iec-allow", Action: rules.ActionAllow, Log: true,
				SourceZones: []string{"lan4"}, DestZones: []string{"station"},
				Sources: []string{"10.60.60.0/24"}, Destinations: []string{"10.70.0.5"},
				Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}},
				ICS:       rules.ICSPredicate{Protocol: "iec104", TypeIDs: []int{45}},
			},
			{
				ID: "c-iec-deny", Action: rules.ActionDeny,
				Sources: []string{"10.60.61.7"},
				ICS:     rules.ICSPredicate{Protocol: "iec104"},
			},
			{
				ID: "d-modbus", Action: rules.ActionAllow,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				ICS:       rules.ICSPredicate{Protocol: "modbus"},
			},
		},
	}
}

const (
	envelopeVerdict = "meta mark set meta mark and 0xf0ffffff or 0x01000000 queue num 100"
	envelopeJump    = "jump iec104_envelope"
)

// envelopeChain is the golden IEC104 envelope chain in each state.
var envelopeChain = map[bool]string{
	true:  "  chain iec104_envelope {\n    " + envelopeVerdict + ";\n  }\n",
	false: "  chain iec104_envelope {\n    drop;\n  }\n",
}

func TestCompileFirewallSteersIEC104EnvelopeBothDirections(t *testing.T) {
	for _, open := range []bool{false, true} {
		c := NewCompiler()
		c.QueueID = 100
		c.NFLogGroup = 7
		c.IEC104EnvelopeOpen = open
		full, err := c.CompileFirewall(iecSnapshot())
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		// The chain is declared once, before the forward chain that jumps to it.
		if strings.Count(full, "chain iec104_envelope") != 1 || !strings.Contains(full, envelopeChain[open]) ||
			strings.Index(full, envelopeChain[open]) > strings.Index(full, "chain forward") {
			t.Fatalf("open=%v: envelope chain missing, duplicated or after forward:\n%s", open, full)
		}
		ruleset := full[strings.Index(full, "chain forward"):]
		want := []string{
			`    iifname { "eth1" } oifname { "eth2" } tcp dport 2404 ip saddr { 10.60.60.0/24 } ip daddr { 10.70.0.5 } ` + envelopeJump + ";\n",
			`    iifname { "eth2" } oifname { "eth1" } tcp sport 2404 ip saddr { 10.70.0.5 } ip daddr { 10.60.60.0/24 } ` + envelopeJump + ";\n",
			`    tcp dport 2404 ip saddr { 10.60.61.7 } ` + envelopeJump + ";\n",
			`    tcp sport 2404 ip daddr { 10.60.61.7 } ` + envelopeJump + ";\n",
			"    tcp dport 502 queue num 100;\n",
			"    ct state { established, related } accept;\n",
			"    tcp dport 2404 accept;\n",
		}
		last := -1
		for _, line := range want {
			i := strings.Index(ruleset, line)
			if i < 0 {
				t.Fatalf("open=%v: missing %q in:\n%s", open, line, ruleset)
			}
			if i < last {
				t.Fatalf("open=%v: %q is out of order in:\n%s", open, line, ruleset)
			}
			last = i
		}
		if n := strings.Count(ruleset, "queue num 100"); n != 1 {
			t.Fatalf("open=%v: forward queue lines = %d, want only the modbus one:\n%s", open, n, ruleset)
		}
		if strings.Contains(ruleset, `log prefix "containd:a-iec-allow`) {
			t.Fatalf("IEC steering must not add an nflog clause:\n%s", ruleset)
		}
		if strings.Count(full, "block_flows") != 2 {
			t.Fatalf("block_flows must appear only as the set and its drop:\n%s", ruleset)
		}
	}
}

// TestIEC104EnvelopeStateTouchesOnlyTheEnvelopeChain: the two states differ
// in the envelope chain's single rule and nowhere else, so the US
// Modbus/DNP3 steering and every non-envelope rule keep their shape.
func TestIEC104EnvelopeStateTouchesOnlyTheEnvelopeChain(t *testing.T) {
	c := NewCompiler()
	c.QueueID = 100
	closed, err := c.CompileFirewall(iecSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	c.IEC104EnvelopeOpen = true
	open, err := c.CompileFirewall(iecSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Replace(closed, envelopeChain[false], envelopeChain[true], 1) != open {
		t.Fatalf("the states differ outside the envelope chain:\nclosed:\n%s\nopen:\n%s", closed, open)
	}
	// A ruleset without IEC rules has no envelope chain in either state.
	modbusOnly := &rules.Snapshot{Default: rules.ActionDeny, Firewall: iecSnapshot().Firewall[3:]}
	a, _ := c.CompileFirewall(modbusOnly)
	c.IEC104EnvelopeOpen = false
	b, _ := c.CompileFirewall(modbusOnly)
	if a != b || strings.Contains(a, "iec104_envelope") {
		t.Fatalf("a US-only ruleset must not change with the envelope state:\n%s", a)
	}
}

func TestIEC104EnvelopeSwitchGolden(t *testing.T) {
	c := NewCompiler()
	c.QueueID = 100
	c.TableName = "containd"
	if got, want := c.IEC104EnvelopeSwitch(true),
		"flush chain inet containd iec104_envelope\nadd rule inet containd iec104_envelope "+envelopeVerdict+"\n"; got != want {
		t.Fatalf("open switch = %q, want %q", got, want)
	}
	if got, want := c.IEC104EnvelopeSwitch(false),
		"flush chain inet containd iec104_envelope\nadd rule inet containd iec104_envelope drop\n"; got != want {
		t.Fatalf("close switch = %q, want %q", got, want)
	}
}

// Without a queue the envelope cannot be inspected; the IEC rule compiles
// like any other rule, as before.
func TestCompileFirewallIEC104WithoutQueueIsUnchanged(t *testing.T) {
	ruleset, err := NewCompiler().CompileFirewall(iecSnapshot())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(ruleset, "queue") || strings.Contains(ruleset, "meta mark") {
		t.Fatalf("no steering without a queue:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, `    iifname { "eth1" } oifname { "eth2" } tcp dport 2404 ip saddr { 10.60.60.0/24 } ip daddr { 10.70.0.5 } accept;`) {
		t.Fatalf("IEC rule not compiled as a plain rule:\n%s", ruleset)
	}
}

func TestCompileFirewallIEC104OutsidePortIsNotSteered(t *testing.T) {
	c := NewCompiler()
	c.QueueID = 100
	snap := &rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{
		ID: "iec-on-502", Action: rules.ActionAllow,
		Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
		ICS:       rules.ICSPredicate{Protocol: "iec104"},
	}}}
	ruleset, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(ruleset, "queue") || c.SteersIEC104(snap) {
		t.Fatalf("an IEC rule that cannot match port 2404 has no envelope:\n%s", ruleset)
	}
}

func TestAdmitsIEC104Port(t *testing.T) {
	cases := []struct {
		name   string
		protos []rules.Protocol
		want   bool
	}{
		{"no protocols", nil, true},
		{"tcp any port", []rules.Protocol{{Name: "tcp"}}, true},
		{"any proto 2404", []rules.Protocol{{Port: "2404"}}, true},
		{"TCP 2404", []rules.Protocol{{Name: "TCP", Port: "2404"}}, true},
		{"range", []rules.Protocol{{Name: "tcp", Port: "2400-2410"}}, true},
		{"second protocol", []rules.Protocol{{Name: "tcp", Port: "502"}, {Name: "tcp", Port: "2404"}}, true},
		{"udp", []rules.Protocol{{Name: "udp", Port: "2404"}}, false},
		{"other port", []rules.Protocol{{Name: "tcp", Port: "502"}}, false},
		{"range below", []rules.Protocol{{Name: "tcp", Port: "1-2403"}}, false},
		{"unparsable", []rules.Protocol{{Name: "tcp", Port: "iec"}}, false},
	}
	for _, tc := range cases {
		if got := admitsIEC104Port(tc.protos); got != tc.want {
			t.Fatalf("%s: admitsIEC104Port = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestEnvelopeMarked(t *testing.T) {
	for mark, want := range map[uint32]bool{
		0x01000000: true,
		0x01000001: true, // other mark bits are kept
		0xf1ffffff: true,
		0x00000000: false,
		0x02000000: false,
		0x03000000: false,
		0x00ffffff: false,
	} {
		if got := EnvelopeMarked(mark); got != want {
			t.Fatalf("EnvelopeMarked(%#x) = %v, want %v", mark, got, want)
		}
	}
}

func TestSteersIEC104(t *testing.T) {
	c := NewCompiler()
	if c.SteersIEC104(iecSnapshot()) {
		t.Fatal("no queue: nothing is steered")
	}
	c.QueueID = 100
	if !c.SteersIEC104(iecSnapshot()) || c.SteersIEC104(&rules.Snapshot{}) || c.SteersIEC104(nil) {
		t.Fatal("SteersIEC104 must follow the IEC rules")
	}
}
