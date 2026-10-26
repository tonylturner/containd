// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// emptyZoneSnapshot names the zone "spare", which has no interfaces, in
// every kind of rule line: plain, conditional, metered, steered and
// partly covered by a zone with interfaces.
func emptyZoneSnapshot() *rules.Snapshot {
	return &rules.Snapshot{
		Default:          rules.ActionDeny,
		ZoneIfaces:       map[string][]string{"ot": {"eth2"}, "spare": nil},
		IdentityBindings: []rules.IdentityBinding{{IP: "10.0.0.5", Identities: []string{"ops"}}},
		Firewall: []rules.Entry{
			{ID: "allow-spare", SourceZones: []string{"spare"}, Action: rules.ActionAllow},
			{ID: "deny-to-spare", DestZones: []string{"spare"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "22"}}, Action: rules.ActionDeny},
			{ID: "allow-ot-or-spare", SourceZones: []string{"spare", "ot"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "443"}}, Action: rules.ActionAllow},
			{ID: "police-spare", DestZones: []string{"spare"}, Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 10}},
			{ID: "ops-spare", SourceZones: []string{"spare"}, Identities: []string{"ops"}, Action: rules.ActionAllow},
			{ID: "iec-spare", SourceZones: []string{"spare"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}},
				ICS: rules.ICSPredicate{Protocol: "iec104"}, Action: rules.ActionAllow},
		},
	}
}

// familySnapshot has IPv6 and mixed-family addresses in every kind of rule
// line, and one rule whose sources and destinations share no family.
func familySnapshot() *rules.Snapshot {
	return &rules.Snapshot{
		Default:    rules.ActionDeny,
		ZoneIfaces: map[string][]string{"it": {"eth1"}, "ot": {"eth2"}},
		IdentityBindings: []rules.IdentityBinding{
			{IP: "10.0.0.5", Identities: []string{"ops"}},
			{IP: "2001:db8::5", Identities: []string{"ops"}},
		},
		Firewall: []rules.Entry{
			{ID: "allow-v6", Sources: []string{"2001:db8:1::/48"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "22"}}, Action: rules.ActionAllow},
			{ID: "deny-mixed", Sources: []string{"10.9.0.0/16", "2001:db8:9::/48"}, Action: rules.ActionDeny},
			{ID: "reset-v6", Destinations: []string{"2001:db8:2::10"}, Protocols: []rules.Protocol{{Name: "udp", Port: "69"}}, Action: rules.ActionReset},
			{ID: "police-mixed", SourceZones: []string{"it"}, DestZones: []string{"ot"}, Destinations: []string{"10.0.2.0/24", "2001:db8:2::/64"},
				Protocols: []rules.Protocol{{Name: "udp", Port: "161"}}, Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 100}},
			{ID: "ops-v6", Identities: []string{"ops"}, Destinations: []string{"2001:db8:2::/64"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "8443"}}, Action: rules.ActionAllow},
			{ID: "tag-mixed", Sources: []string{"10.9.0.0/16", "2001:db8:9::/48"}, Action: rules.ActionTag, Tag: "lab"},
			{ID: "iec-mixed", Sources: []string{"2001:db8:3::/64"}, Destinations: []string{"10.0.3.5/32", "2001:db8:4::5/128"},
				Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}}, ICS: rules.ICSPredicate{Protocol: "iec104"}, Action: rules.ActionAllow},
			{ID: "modbus-ops", Identities: []string{"ops"}, Destinations: []string{"10.1.0.0/24", "2001:db8:1::/64"},
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}, ICS: rules.ICSPredicate{Protocol: "modbus"}, Action: rules.ActionAllow},
			{ID: "disjoint", Sources: []string{"10.0.0.0/8"}, Destinations: []string{"2001:db8::/32"}, Action: rules.ActionAllow},
		},
	}
}

// loweringGoldens are the snapshots with a pinned policy table, each with
// the compiler it is compiled with; the kernel test loads each into nft.
var loweringGoldens = []struct {
	file     string
	snapshot func() *rules.Snapshot
	compiler func() *Compiler
}{
	{"testdata/identity_schedule_policy.nft", goldenSnapshot, goldenCompiler},
	{"testdata/empty_zone_policy.nft", emptyZoneSnapshot, goldenCompiler},
	{"testdata/address_family_policy.nft", familySnapshot, goldenCompiler},
}

// policyTable cuts the policy table out of a compiled script.
func policyTable(t *testing.T, script string) string {
	t.Helper()
	start := strings.Index(script, "table inet containd_policy {")
	end := strings.Index(script, "\n}\n")
	if start < 0 || end < start {
		t.Fatalf("no policy table in:\n%s", script)
	}
	return script[start : end+3]
}

// TestLoweringGoldens pins the policy table of each golden snapshot. Set
// CONTAIND_UPDATE_GOLDEN=1 to rewrite the files after a deliberate change.
func TestLoweringGoldens(t *testing.T) {
	for _, g := range loweringGoldens {
		t.Run(g.file, func(t *testing.T) {
			out, err := g.compiler().CompileFirewall(g.snapshot())
			if err != nil {
				t.Fatal(err)
			}
			assertDeclaredSets(t, out)
			got := policyTable(t, out)
			if os.Getenv("CONTAIND_UPDATE_GOLDEN") == "1" {
				if err := os.WriteFile(g.file, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(g.file)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("policy table differs from %s:\n%s", g.file, got)
			}
		})
	}
}

// TestRulesThatMatchNothingWarn: a rule whose zones have no interfaces or
// whose addresses share no family has no lines and a warning naming why.
func TestRulesThatMatchNothingWarn(t *testing.T) {
	type warning struct {
		rule  string
		pred  RulePredicate
		zones string
	}
	for name, tc := range map[string]struct {
		snap *rules.Snapshot
		want []warning
	}{
		"empty zones": {emptyZoneSnapshot(), []warning{
			{"allow-spare", PredicateZone, "spare"}, {"deny-to-spare", PredicateZone, "spare"},
			{"iec-spare", PredicateZone, "spare"}, {"ops-spare", PredicateZone, "spare"}, {"police-spare", PredicateZone, "spare"},
		}},
		"address families": {familySnapshot(), []warning{{"disjoint", PredicateAddressFamily, ""}}},
	} {
		t.Run(name, func(t *testing.T) {
			var got []warning
			for _, w := range NewCompiler().RuleWarnings(tc.snap) {
				got = append(got, warning{w.RuleID, w.Predicate, strings.Join(w.Zones, ",")})
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("warnings = %+v, want %+v", got, tc.want)
			}
		})
	}
	w := NewCompiler().RuleWarnings(&rules.Snapshot{Firewall: []rules.Entry{{ID: "r", SourceZones: []string{"a", "b"}, DestZones: []string{"a"}, Action: rules.ActionAllow}}})
	if len(w) != 1 || w[0].Message != "no interface is assigned to zones a, b; the rule matches nothing until one is" {
		t.Fatalf("warnings = %+v", w)
	}
}

// TestInterfaceNames: only names Linux accepts for a device and nft can
// match exactly reach a ruleset, from every source of interface names.
func TestInterfaceNames(t *testing.T) {
	for _, name := range []string{"eth0", "lan1", "wan", "br-0.10", "enp0s31f6", "a", "abcdefghijklmno", "veth@1", "é1"} {
		if err := ValidateInterfaceName(name); err != nil {
			t.Errorf("%q refused: %v", name, err)
		}
	}
	bad := []string{"", ".", "..", "abcdefghijklmnop", "eth 0", "eth\t0", "eth/0", "eth:0", `eth"0`, "eth*", `eth\0`, "eth\x00", "eth\x7f", "eth\xa0"}
	for _, name := range bad {
		if err := ValidateInterfaceName(name); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
	injected := `x" } accept; #`
	allow := []rules.Entry{{ID: "r", SourceZones: []string{"lan"}, Action: rules.ActionAllow}}
	for name, c := range map[string]func() (*Compiler, *rules.Snapshot){
		"zone": func() (*Compiler, *rules.Snapshot) {
			return NewCompiler(), &rules.Snapshot{ZoneIfaces: map[string][]string{"lan": {injected}}, Firewall: allow}
		},
		"unused zone": func() (*Compiler, *rules.Snapshot) {
			return NewCompiler(), &rules.Snapshot{ZoneIfaces: map[string][]string{"spare": {"abcdefghijklmnop"}}}
		},
		"local input": func() (*Compiler, *rules.Snapshot) {
			return NewCompiler(), &rules.Snapshot{LocalInput: []rules.LocalServiceRule{{ID: "dhcp", Ifaces: []string{injected}, Proto: "udp", Port: 1067}}}
		},
		"engine API": func() (*Compiler, *rules.Snapshot) {
			c := NewCompiler()
			c.EngineAPI = &EngineAPIPath{Device: injected, Addr: netip.MustParseAddr("192.0.2.1"), Port: 8081}
			return c, &rules.Snapshot{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, snap := c()
			if out, err := c.CompileFirewall(snap); err == nil || !strings.Contains(err.Error(), "invalid interface name") {
				t.Fatalf("compiled with an invalid interface name: %v\n%s", err, out)
			}
		})
	}
}

// TestAddressesAreParsed: rule addresses reach nft only as parsed IPv4 or
// IPv6 addresses and prefixes.
func TestAddressesAreParsed(t *testing.T) {
	for _, addr := range []string{"10.0.0.0/8 } accept; #", "host.example", "fe80::1%eth0", "10.0.0.0/33"} {
		snap := &rules.Snapshot{Firewall: []rules.Entry{{ID: "r", Destinations: []string{addr}, Action: rules.ActionAllow}}}
		if out, err := NewCompiler().CompileFirewall(snap); err == nil {
			t.Fatalf("%q compiled:\n%s", addr, out)
		}
	}
	lines, err := compileEntryWithoutCounters(rules.Entry{ID: "r", Sources: []string{" 10.1.0.0/16", "2001:db8::/32 ", "::ffff:10.2.0.1"}, Action: rules.ActionDeny}, nil, 0, 0)
	if want := []string{"ip saddr { 10.1.0.0/16 } drop", "ip6 saddr { 2001:db8::/32, ::ffff:10.2.0.1 } drop"}; err != nil || !reflect.DeepEqual(lines, want) {
		t.Fatalf("lines = %q, %v; want %q", lines, err, want)
	}
}
