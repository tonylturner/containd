// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Listings of a pre-0.1.35 inet containd table (nft 1.1.7, rules trimmed).
const (
	legacyTableJSON = `{"nftables": [{"metainfo": {"version": "1.1.7", "json_schema_version": 1}},
{"table": {"family": "inet", "name": "containd", "handle": 1}},
{"chain": {"family": "inet", "table": "containd", "name": "iec104_envelope", "handle": 1}},
{"chain": {"family": "inet", "table": "containd", "name": "input", "handle": 2, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
{"chain": {"family": "inet", "table": "containd", "name": "forward", "handle": 3, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
{"chain": {"family": "inet", "table": "containd", "name": "prerouting", "handle": 4, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}},
{"chain": {"family": "inet", "table": "containd", "name": "postrouting", "handle": 5, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
{"set": {"family": "inet", "name": "zone_lan_ifaces", "table": "containd", "type": "ifname", "handle": 6}},
{"set": {"family": "inet", "name": "block_hosts", "table": "containd", "type": "ipv4_addr", "handle": 7, "flags": ["timeout"]}},
{"set": {"family": "inet", "name": "block_flows", "table": "containd", "type": ["ipv4_addr", "ipv4_addr", "inet_service"], "handle": 8, "flags": ["timeout"]}},
{"rule": {"family": "inet", "table": "containd", "chain": "iec104_envelope", "handle": 9, "expr": [{"drop": null}]}}]}`
	legacyFlowsJSON = `{"nftables": [{"metainfo": {"version": "1.1.7", "json_schema_version": 1}},
{"set": {"family": "inet", "name": "block_flows", "table": "containd", "type": ["ipv4_addr", "ipv4_addr", "inet_service"], "handle": 8, "flags": ["timeout"],
"elem": [{"concat": ["10.0.0.1", "10.0.0.2", 502]}, {"elem": {"val": {"concat": ["198.18.90.2", "198.18.100.2", 18099]}, "timeout": 3600, "expires": 3599}},
{"elem": {"val": {"concat": ["198.18.90.3", "198.18.100.2", 18099]}, "timeout": 3600, "expires": 0}}]}}]}`
)

// currentLayout is the layout the compiler installs.
func currentLayout() TableLayout {
	l := TableLayout{Exists: true, Chains: []LiveChain{{Name: "revocations"}}}
	for _, ch := range dynamicChains {
		l.Chains = append(l.Chains, LiveChain{Name: ch.name, Type: "filter", Hook: ch.hook, Policy: "accept", Prio: dynamicChainPriority})
	}
	for _, set := range dynamicSets() {
		l.Objects = append(l.Objects, LiveObject{Kind: "set", Name: set[0], Type: set[1], Flags: []string{"timeout"}})
	}
	return l
}

func TestParseLegacyTable(t *testing.T) {
	l, err := parseTableLayout([]byte(legacyTableJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Chains) != 5 || l.Chains[1] != (LiveChain{Name: "input", Type: "filter", Hook: "input", Policy: "drop"}) || l.Chains[3].Prio != -100 {
		t.Fatalf("chains = %+v", l.Chains)
	}
	if len(l.Objects) != 3 || l.Objects[2].Type != legacyFlowType || l.Objects[0].Type != "ifname" || l.Objects[1].Flags[0] != "timeout" {
		t.Fatalf("objects = %+v", l.Objects)
	}
	flows, err := parseLegacyFlowBlocks([]byte(legacyFlowsJSON))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"10.0.0.1 . 10.0.0.2 . tcp . 502, 10.0.0.1 . 10.0.0.2 . udp . 502",
		"198.18.90.2 . 198.18.100.2 . tcp . 18099 timeout 3599s, 198.18.90.2 . 198.18.100.2 . udp . 18099 timeout 3599s",
	}
	if strings.Join(flows, "\n") != strings.Join(want, "\n") {
		t.Fatalf("legacy flows:\n%s", strings.Join(flows, "\n"))
	}
	if _, err := parseLegacyFlowBlocks([]byte(strings.Replace(legacyFlowsJSON, `"10.0.0.1"`, `"2001:db8::1"`, 1))); err == nil {
		t.Fatal("accepted a legacy element containd could not have written")
	}
	if _, err := parseTableLayout([]byte(`{"nftables": [{"tunnel": {"name": "x"}}]}`)); err == nil {
		t.Fatal("accepted an object it cannot delete")
	}
}

func TestConvergeLegacyTable(t *testing.T) {
	l, err := parseTableLayout([]byte(legacyTableJSON))
	if err != nil {
		t.Fatal(err)
	}
	l.LegacyFlowBlocks = []string{"10.0.0.1 . 10.0.0.2 . tcp . 502, 10.0.0.1 . 10.0.0.2 . udp . 502"}
	c := NewCompiler()
	compiled, err := c.CompileFirewall(&rules.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	got := c.InstallScript(l, "RETIRE\n", compiled)
	want := "flush chain inet containd iec104_envelope\nflush chain inet containd input\nflush chain inet containd forward\n" +
		"flush chain inet containd prerouting\nflush chain inet containd postrouting\n" +
		"delete chain inet containd iec104_envelope\ndelete chain inet containd input\ndelete chain inet containd forward\n" +
		"delete chain inet containd prerouting\ndelete chain inet containd postrouting\n" +
		"delete set inet containd zone_lan_ifaces\ndelete set inet containd block_flows\n" +
		"RETIRE\n" + compiled +
		"add element inet containd block_flows { 10.0.0.1 . 10.0.0.2 . tcp . 502, 10.0.0.1 . 10.0.0.2 . udp . 502 }\n"
	if got != want {
		t.Fatalf("install script:\n%s\nwant:\n%s", got, want)
	}
}

func TestConvergeKeepsTheCurrentLayout(t *testing.T) {
	c := NewCompiler()
	if got := c.InstallScript(currentLayout(), "", "X\n"); got != "X\n" {
		t.Fatalf("current layout changed: %q", got)
	}
	if got := c.InstallScript(TableLayout{}, "", "X\n"); got != "X\n" {
		t.Fatalf("absent table changed: %q", got)
	}
	// Any deviation of a current chain or set recreates it.
	for name, change := range map[string]func(*TableLayout){
		"input priority":   func(l *TableLayout) { l.Chains[1].Prio = 0 },
		"output policy":    func(l *TableLayout) { l.Chains[3].Policy = "drop" },
		"revocations hook": func(l *TableLayout) { l.Chains[0].Hook, l.Chains[0].Type = "input", "filter" },
		"block_hosts type": func(l *TableLayout) { l.Objects[0].Type = "ipv6_addr" },
		"revoke4 flags":    func(l *TableLayout) { l.Objects[2].Flags = []string{"interval", "timeout"} },
		"same-named map":   func(l *TableLayout) { l.Objects[1].Kind = "map" },
		"extra counter":    func(l *TableLayout) { l.Objects = append(l.Objects, LiveObject{Kind: "counter", Name: "c"}) },
		"extra base chain": func(l *TableLayout) {
			l.Chains = append(l.Chains, LiveChain{Name: "x", Type: "nat", Hook: "postrouting"})
		},
	} {
		l := currentLayout()
		change(&l)
		got := c.InstallScript(l, "", "X\n")
		if !strings.HasPrefix(got, "flush chain inet containd revocations\n") || strings.Count(got, "delete ") != 1 || !strings.HasSuffix(got, "X\n") {
			t.Fatalf("%s: %q", name, got)
		}
	}
}
