// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package enforce

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestCompileFirewallBasic(t *testing.T) {
	compiler := NewCompiler()
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{ID: "10", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "tcp", Port: "80"}}},
			{ID: "20", Action: rules.ActionDeny, Sources: []string{"10.0.0.0/8"}},
		},
	}
	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(ruleset, "table inet containd") {
		t.Fatalf("missing table: %s", ruleset)
	}
	if !strings.Contains(ruleset, "add set inet containd block_hosts") || !strings.Contains(ruleset, "add set inet containd block_flows") {
		t.Fatalf("missing block sets: %s", ruleset)
	}
	if !strings.Contains(ruleset, "policy drop") {
		t.Fatalf("missing default drop policy")
	}
	if !strings.Contains(ruleset, "tcp dport 80 goto ordered_s2_rule_0") {
		t.Fatalf("missing allow rule: %s", ruleset)
	}
	if !strings.Contains(ruleset, "ip saddr { 10.0.0.0/8 } goto ordered_s2_rule_1") {
		t.Fatalf("missing deny rule: %s", ruleset)
	}
}

// Configured order, not action or ID, controls terminal precedence.
func TestCompileFirewallPreservesTerminalOrder(t *testing.T) {
	compiler := NewCompiler()
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		ZoneIfaces: map[string][]string{
			"lan1": {"eth2"},
			"lan2": {"eth3"},
		},
		Firewall: []rules.Entry{
			// The broad DENY deliberately precedes the narrow ALLOW.
			{
				ID:          "deny-ot-to-field-broad",
				SourceZones: []string{"lan1"},
				DestZones:   []string{"lan2"},
				Protocols:   []rules.Protocol{{Name: "tcp", Port: "8080"}},
				Action:      rules.ActionDeny,
			},
			{
				ID:          "rtac-to-field-narrow",
				SourceZones: []string{"lan1"},
				DestZones:   []string{"lan2"},
				Sources:     []string{"10.30.30.20/32"},
				Protocols:   []rules.Protocol{{Name: "tcp", Port: "8080"}},
				Action:      rules.ActionAllow,
			},
		},
	}
	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	allowIdx := strings.Index(ruleset, "ip saddr { 10.30.30.20/32 } goto ordered_s2_rule_1")
	denyIdx := strings.Index(ruleset, "tcp dport 8080 goto ordered_s2_rule_0")
	if allowIdx < 0 || denyIdx < 0 {
		t.Fatalf("expected both allow and deny lines, got:\n%s", ruleset)
	}
	if allowIdx < denyIdx {
		t.Errorf("configured DENY must precede ALLOW; got allow@%d deny@%d in:\n%s",
			allowIdx, denyIdx, ruleset)
	}
}

// TestCompileFirewallMultiProtocol pins the fix for a real-world bug:
// rules declaring multiple protocols (e.g. an enterprise->field allow
// for tcp/502 + tcp/20000 + tcp/8080) used to compile to a single nft
// line for the FIRST protocol only, silently dropping the rest. The
// substation lab in RangerDanger hit this — Modbus and DNP3 traffic
// black-holed under both weak and improved policies because only the
// 8080 line ever made it to the kernel ruleset.
func TestCompileFirewallMultiProtocol(t *testing.T) {
	compiler := NewCompiler()
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{
				ID:     "multi",
				Action: rules.ActionAllow,
				Protocols: []rules.Protocol{
					{Name: "tcp", Port: "502"},
					{Name: "tcp", Port: "20000"},
					{Name: "tcp", Port: "8080"},
				},
			},
		},
	}
	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, want := range []string{
		"tcp dport 502 goto ordered_s2_rule_0",
		"tcp dport 20000 goto ordered_s2_rule_0",
		"tcp dport 8080 goto ordered_s2_rule_0",
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("expected %q in compiled ruleset, got:\n%s", want, ruleset)
		}
	}
}

func TestCompileFirewallNoProtocolsStillEmits(t *testing.T) {
	// Rules constrained only by zones / sources should still compile.
	compiler := NewCompiler()
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{ID: "no-proto", Action: rules.ActionDeny, Sources: []string{"10.10.10.0/24"}},
		},
	}
	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(ruleset, "ip saddr { 10.10.10.0/24 } goto ordered_s2_rule_0") {
		t.Fatalf("expected source-only deny line, got:\n%s", ruleset)
	}
}

func TestCompileFirewallZoneBindings(t *testing.T) {
	compiler := NewCompiler()
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		ZoneIfaces: map[string][]string{
			"wan": {"wan"},
			"lan": {"lan2", "lan3"},
		},
		Firewall: []rules.Entry{
			{
				ID:          "z1",
				SourceZones: []string{"lan"},
				DestZones:   []string{"wan"},
				Protocols:   []rules.Protocol{{Name: "tcp", Port: "80"}},
				Action:      rules.ActionAllow,
			},
		},
	}
	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(ruleset, "set zone_6c616e") || !strings.Contains(ruleset, "type ifname") {
		t.Fatalf("missing zone iface sets: %s", ruleset)
	}
	if !strings.Contains(ruleset, "iifname { \"lan2\", \"lan3\" }") || !strings.Contains(ruleset, "oifname { \"wan\" }") {
		t.Fatalf("missing iif/oif bindings: %s", ruleset)
	}
}

func TestCompileFirewallQueueRulesForDPIEntries(t *testing.T) {
	compiler := NewCompiler()
	compiler.QueueID = 42

	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{
				ID:        "ics1",
				Action:    rules.ActionAllow,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				ICS:       rules.ICSPredicate{Mode: "enforce", Protocol: "modbus"},
			},
			{
				ID:        "web",
				Action:    rules.ActionAllow,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "80"}},
			},
		},
	}
	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// The ICS entry should use queue instead of accept.
	if !strings.Contains(ruleset, "tcp dport 502 jump ics_enforce_queue") {
		t.Fatalf("expected queue rule for ICS entry, got:\n%s", ruleset)
	}
	// The non-ICS entry should still use accept.
	if !strings.Contains(ruleset, "tcp dport 80 goto ordered_s2_rule_1") {
		t.Fatalf("expected accept rule for non-ICS entry, got:\n%s", ruleset)
	}
}

func TestCompileFirewallNoQueueWithoutQueueID(t *testing.T) {
	compiler := NewCompiler()
	// QueueID is 0 (default) — no queue rules should be emitted.
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{
				ID:        "ics1",
				Action:    rules.ActionAllow,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				ICS:       rules.ICSPredicate{Mode: "enforce", Protocol: "modbus"},
			},
		},
	}
	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(ruleset, "queue") {
		t.Fatalf("did not expect queue rule when QueueID is 0, got:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, "tcp dport 502 goto ordered_s2_rule_0") {
		t.Fatalf("expected accept rule, got:\n%s", ruleset)
	}
}

func TestCompileFirewallEmitsLogClauseForL4Rules(t *testing.T) {
	compiler := NewCompiler()
	compiler.NFLogGroup = 100

	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{
				ID:        "deny-ent-to-field",
				Action:    rules.ActionDeny,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				Log:       true,
			},
			{
				ID:        "allow-rtac-to-field",
				Action:    rules.ActionAllow,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				Sources:   []string{"10.30.30.20/32"},
				Log:       true,
			},
			{
				ID:        "silent-deny",
				Action:    rules.ActionDeny,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "23"}},
				// Log left as false — no log clause expected.
			},
		},
	}
	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	wantDeny := `log prefix "containd:deny-ent-to-field:DENY " group 100`
	if !strings.Contains(ruleset, wantDeny) {
		t.Fatalf("expected deny rule to include log clause %q, got:\n%s", wantDeny, ruleset)
	}
	wantAllow := `log prefix "containd:allow-rtac-to-field:ALLOW " group 100`
	if !strings.Contains(ruleset, wantAllow) {
		t.Fatalf("expected allow rule to include log clause %q, got:\n%s", wantAllow, ruleset)
	}
	// The Log:false rule must NOT have a log clause.
	if strings.Contains(ruleset, "silent-deny") && strings.Contains(ruleset, `containd:silent-deny`) {
		t.Fatalf("did not expect log clause on silent-deny rule, got:\n%s", ruleset)
	}
}

func TestCompileFirewallSuppressesLogForDPIRules(t *testing.T) {
	// DPI-eligible rules (those with an ICS predicate) route through
	// NFQUEUE. The userspace handler emits firewall.rule.hit events via
	// EvaluateVerdict, so adding an nflog clause here would double-count
	// the event in the consumer-facing event store.
	compiler := NewCompiler()
	compiler.QueueID = 42
	compiler.NFLogGroup = 100

	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{
				ID:        "modbus-fc-guard",
				Action:    rules.ActionDeny,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				ICS:       rules.ICSPredicate{Mode: "enforce", Protocol: "modbus", FunctionCode: []uint8{5, 6}},
				Log:       true,
			},
		},
	}
	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(ruleset, "log prefix") {
		t.Fatalf("did not expect log clause on DPI-eligible rule, got:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, "tcp dport 502 jump ics_enforce_queue") {
		t.Fatalf("expected queue verdict on DPI rule, got:\n%s", ruleset)
	}
}

func TestCompileFirewallNoLogWithoutNFLogGroup(t *testing.T) {
	// NFLogGroup is 0 (default) — no log clauses should be emitted even
	// when Log:true is set on rules. This preserves backward compatibility
	// for deployments that haven't wired the nflog consumer.
	compiler := NewCompiler()
	// NFLogGroup intentionally left at 0.
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{
				ID:        "deny-ent",
				Action:    rules.ActionDeny,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				Log:       true,
			},
		},
	}
	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(ruleset, "log prefix") {
		t.Fatalf("did not expect log clause when NFLogGroup is 0, got:\n%s", ruleset)
	}
}

func TestLogPrefixTruncatesLongRuleID(t *testing.T) {
	// nflog kernel-side prefix is 64 bytes. Verify long rule IDs are
	// truncated to keep the full prefix string under that limit with room
	// for "containd:" + ":<ACTION> " framing.
	longID := strings.Repeat("a", 60)
	got := logPrefix(longID, rules.ActionDeny)
	// 9 ("containd:") + 40 (truncated id) + 6 (":DENY ") = 55 bytes.
	if len(got) > 64 {
		t.Fatalf("expected prefix <= 64 bytes, got %d: %q", len(got), got)
	}
	if !strings.HasPrefix(got, "containd:aaaa") {
		t.Fatalf("unexpected prefix shape: %q", got)
	}
	if !strings.HasSuffix(got, ":DENY ") {
		t.Fatalf("expected DENY suffix, got: %q", got)
	}
}

func TestIsDPIEligible(t *testing.T) {
	tests := []struct {
		name     string
		entry    rules.Entry
		eligible bool
	}{
		{
			name:     "ICS modbus entry",
			entry:    rules.Entry{ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "modbus"}},
			eligible: true,
		},
		{
			name:     "ICS dnp3 entry",
			entry:    rules.Entry{ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "dnp3"}},
			eligible: true,
		},
		{
			name:     "plain rule no ICS",
			entry:    rules.Entry{Action: rules.ActionAllow},
			eligible: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDPIEligible(tt.entry); got != tt.eligible {
				t.Fatalf("isDPIEligible() = %v, want %v", got, tt.eligible)
			}
		})
	}
}

func TestNftUpdaterArgsFormatting(t *testing.T) {
	u := NewNftUpdater("containd")
	ip := net.ParseIP("10.1.2.3")
	args := u.buildBlockHostArgs(ip, 5*time.Second)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "block_hosts") || !strings.Contains(joined, "10.1.2.3 timeout 5s") {
		t.Fatalf("unexpected host args: %s", joined)
	}

	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")
	fargs := u.buildBlockFlowArgs(src, dst, "tcp", "502", 0)
	fjoined := strings.Join(fargs, " ")
	if !strings.Contains(fjoined, "block_flows") || !strings.Contains(fjoined, "10.0.0.1 . 10.0.0.2 . tcp . 502") {
		t.Fatalf("unexpected flow args: %s", fjoined)
	}
}

func TestFlowBlockKeysIncludeProtocol(t *testing.T) {
	u := NewNftUpdater("containd")
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	tcp := strings.Join(u.buildBlockFlowArgs(src, dst, "tcp", "502", 5*time.Second), " ")
	udp := strings.Join(u.buildBlockFlowArgs(src, dst, "udp", "502", 5*time.Second), " ")
	if tcp == udp || !strings.Contains(tcp, ". tcp . 502 timeout 5s") || !strings.Contains(udp, ". udp . 502 timeout 5s") {
		t.Fatalf("protocol collision: tcp=%q udp=%q", tcp, udp)
	}
	text, err := NewCompiler().CompileFirewall(&rules.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "type ipv4_addr . ipv4_addr . inet_proto . inet_service;") {
		t.Fatalf("set type omits protocol:\n%s", text)
	}
	// The blocks chain hooks forward before the policy chain (priority 0)
	// with its established accept, and a drop there is final.
	lookup := "add rule inet containd forward meta l4proto { tcp, udp } ip saddr . ip daddr . meta l4proto . th dport @block_flows drop\n"
	if !strings.Contains(text, lookup) || !strings.Contains(text, "add chain inet containd forward { type filter hook forward priority -10;") {
		t.Fatalf("protocol-aware block must drop in the earlier blocks chain:\n%s", text)
	}
}

func TestFlowBlockRejectsInvalidPort(t *testing.T) {
	u := NewNftUpdater("containd")
	// An invalid input must fail validation, without attempting to run nft.
	u.Path = "/nonexistent/nft"
	for _, port := range []string{"0", "-1", "65536", "not-a-port", "502; accept"} {
		err := u.BlockFlowTemp(context.Background(), net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), "tcp", port, time.Second)
		if err == nil || !strings.Contains(err.Error(), "invalid dport") {
			t.Fatalf("port %q: %v", port, err)
		}
	}
}

func TestCompileFirewallNATChains(t *testing.T) {
	compiler := NewCompiler()
	snap := &rules.Snapshot{
		Default:        rules.ActionDeny,
		ForwardMatches: map[string]rules.ForwardMatch{"pf1": {Enabled: true, IngressDevices: []string{"wan0"}, Protocol: "tcp", ListenPort: 443, Backend: netip.MustParseAddrPort("10.0.0.10:8443"), AllowedSources: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/32"), netip.MustParsePrefix("203.0.113.0/24")}}},
		ZoneIfaces: map[string][]string{
			"wan": {"wan0"},
			"lan": {"lan0"},
		},
		NAT: rules.NATConfig{
			Enabled:     true,
			EgressZone:  "wan",
			SourceZones: []string{"lan"},
			PortForwards: []rules.PortForward{{
				ID:             "pf1",
				Enabled:        true,
				IngressZone:    "wan",
				Proto:          "tcp",
				ListenPort:     443,
				DestIP:         "10.0.0.10",
				DestPort:       8443,
				AllowedSources: []string{"198.51.100.10", "203.0.113.0/24"},
			}},
		},
	}

	ruleset, err := compileWithoutCounters(compiler, snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(ruleset, "chain prerouting") {
		t.Fatalf("missing prerouting chain:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, `iifname "wan0" ip daddr @local4_77616e30 ip saddr { 198.51.100.10/32, 203.0.113.0/24 } tcp dport 443 counter ct mark set ct mark | 0x00000001 dnat ip to 10.0.0.10:8443`) {
		t.Fatalf("missing prerouting DNAT rule:\n%s", ruleset)
	}
	if strings.Contains(ruleset, "ct status dnat") {
		t.Fatal("implicit DNAT permission survived")
	}

	if !strings.Contains(ruleset, "chain postrouting") {
		t.Fatalf("missing postrouting chain:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, `iifname @zone_6c616e oifname @zone_77616e masquerade`) {
		t.Fatalf("missing zone masquerade rule:\n%s", ruleset)
	}
}

func TestCompileLocalInputRule(t *testing.T) {
	line, err := compileLocalInputRule(rules.LocalServiceRule{
		ID:    "ssh",
		Zone:  "mgmt",
		Proto: "tcp",
		Port:  22,
	}, zoneIndex{"mgmt": {`"eth7"`}})
	if err != nil {
		t.Fatalf("compileLocalInputRule(valid): %v", err)
	}
	if line != `iifname @zone_6d676d74 tcp dport 22 accept` {
		t.Fatalf("unexpected local input rule %q", line)
	}

	line, err = compileLocalInputRule(rules.LocalServiceRule{
		ID:     "dns",
		Ifaces: []string{"eth1", "eth0"},
		Proto:  "udp",
		Port:   53,
	}, nil)
	if err != nil {
		t.Fatalf("compileLocalInputRule(ifaces): %v", err)
	}
	if line != `iifname { "eth0", "eth1" } udp dport 53 accept` {
		t.Fatalf("unexpected iface local input rule %q", line)
	}

	if _, err := compileLocalInputRule(rules.LocalServiceRule{ID: "bad", Proto: "icmp", Port: 53}, nil); err == nil {
		t.Fatal("expected invalid proto error")
	}
}

func TestValidateCIDRList(t *testing.T) {
	validated, err := validateCIDRList([]string{" 198.51.100.10 ", "203.0.113.0/24", ""})
	if err != nil {
		t.Fatalf("validateCIDRList(valid): %v", err)
	}
	if got := strings.Join(validated, ","); got != "198.51.100.10,203.0.113.0/24" {
		t.Fatalf("validateCIDRList(valid) = %q", got)
	}
	if _, err := validateCIDRList([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected invalid CIDR list error")
	}
}

func TestLogPrefixSanitizesUnsafeRuleIDChars(t *testing.T) {
	// Config validation doesn't forbid `:`, `"`, spaces, or other
	// shell/quote-breaking characters in rule IDs. The producer side
	// must sanitize so the emitted nft `log prefix "..."` clause stays
	// well-formed AND the consumer-side regex (also restricted to
	// [A-Za-z0-9_-]) can match it.
	cases := []struct {
		in   string
		want string
	}{
		{"plain-id", `containd:plain-id:DENY `},
		{"id_with_underscores", `containd:id_with_underscores:DENY `},
		{`id"with"quotes`, `containd:id_with_quotes:DENY `},
		{"id:with:colons", `containd:id_with_colons:DENY `},
		{"id with spaces", `containd:id_with_spaces:DENY `},
		{"id*with$shell?chars", `containd:id_with_shell_chars:DENY `},
		{"id/with/slashes", `containd:id_with_slashes:DENY `},
	}
	for _, c := range cases {
		c := c
		t.Run(c.in, func(t *testing.T) {
			got := logPrefix(c.in, rules.ActionDeny)
			if got != c.want {
				t.Errorf("logPrefix(%q): got %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestLogPrefixSanitizationFitsBudgetAfterTruncation(t *testing.T) {
	// 50-char ID with mixed safe/unsafe chars — sanitize then truncate
	// to maxIDLen=40 to keep the full prefix under the 64-byte nflog
	// limit.
	id := "rule-id-with-many-bad?chars*and/slashes-everywhere"
	got := logPrefix(id, rules.ActionAllow)
	if len(got) > 64 {
		t.Fatalf("prefix exceeds 64-byte budget: %d bytes %q", len(got), got)
	}
}

// TestCompileEntryProtocolMatches pins the nft match emitted per protocol.
// A TCP/UDP rule without a port used to compile to a bare "tcp" token,
// which nft rejects, failing the whole ruleset apply.
func TestCompileEntryProtocolMatches(t *testing.T) {
	cases := []struct {
		name  string
		proto rules.Protocol
		want  string
	}{
		{"tcp port", rules.Protocol{Name: "tcp", Port: "502"}, "tcp dport 502 ip saddr { 172.30.0.4 } goto ordered_s2_rule_0"},
		{"tcp range", rules.Protocol{Name: "tcp", Port: "1-65535"}, "tcp dport 1-65535 ip saddr { 172.30.0.4 } goto ordered_s2_rule_0"},
		{"tcp no port", rules.Protocol{Name: "tcp"}, "meta l4proto tcp ip saddr { 172.30.0.4 } goto ordered_s2_rule_0"},
		{"udp port", rules.Protocol{Name: "udp", Port: "53"}, "udp dport 53 ip saddr { 172.30.0.4 } goto ordered_s2_rule_0"},
		{"udp no port", rules.Protocol{Name: "udp"}, "meta l4proto udp ip saddr { 172.30.0.4 } goto ordered_s2_rule_0"},
		{"icmp", rules.Protocol{Name: "icmp"}, "meta l4proto icmp ip saddr { 172.30.0.4 } goto ordered_s2_rule_0"},
		{"upper case", rules.Protocol{Name: "TCP"}, "meta l4proto tcp ip saddr { 172.30.0.4 } goto ordered_s2_rule_0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := rules.Entry{ID: "r", Action: rules.ActionAllow, Sources: []string{"172.30.0.4"}, Protocols: []rules.Protocol{tc.proto}}
			lines, err := headerLinesText(e, "goto ordered_s2_rule_0")
			if err != nil {
				t.Fatalf("headerLines: %v", err)
			}
			if len(lines) != 1 || lines[0] != tc.want {
				t.Fatalf("lines = %q, want [%q]", lines, tc.want)
			}
		})
	}
}

func TestCompileEntryRejectsInvalidProtocols(t *testing.T) {
	for name, p := range map[string]rules.Protocol{
		"icmp port":   {Name: "icmp", Port: "8"},
		"port only":   {Port: "502"},
		"unsupported": {Name: "sctp"},
		"injection":   {Name: "tcp accept; flush ruleset"},
	} {
		t.Run(name, func(t *testing.T) {
			e := rules.Entry{ID: "r", Action: rules.ActionAllow, Protocols: []rules.Protocol{p}}
			if lines, err := headerLinesText(e, "goto ordered_s2_rule_0"); err == nil {
				t.Fatalf("expected error, got %q", lines)
			}
		})
	}
}

func TestProtocolMatchPortSerialization(t *testing.T) {
	for _, tc := range []struct{ port, want string }{
		{"0502", "tcp dport 502"}, {"0001-0002", "tcp dport 1-2"}, {"0-65535", "tcp dport 0-65535"},
		{"80 accept", ""}, {"1-0", ""}, {"65536", ""}, {"1; drop", ""}, {"+80", ""},
	} {
		got, err := protocolMatch(rules.Protocol{Name: "tcp", Port: tc.port})
		if got != tc.want || (err != nil) != (tc.want == "") {
			t.Errorf("port %q: got %q, %v; want %q", tc.port, got, err, tc.want)
		}
	}
}
