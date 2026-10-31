// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"net/netip"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/markabi"
)

func forwardFixture() (ForwardMatch, EvalContext, map[string][]netip.Addr) {
	f := ForwardMatch{Enabled: true, IngressDevices: []string{"wan0"}, Protocol: "tcp", ListenPort: 1502,
		Backend: netip.MustParseAddrPort("10.0.0.8:502"), AllowedSources: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}
	ctx := l4Ctx("198.51.100.2", "10.0.0.8", "tcp", "502")
	ctx.IngressDevice = "wan0"
	ctx.Conntrack = &ConntrackContext{Mark: markabi.OwnedForwardCtBit, Original: ConnectionTuple{
		Source: netip.MustParseAddrPort("198.51.100.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.2:1502")},
		Reply: ConnectionTuple{Source: f.Backend, Destination: netip.MustParseAddrPort("198.51.100.2:40000")}}
	return f, ctx, map[string][]netip.Addr{"wan0": {netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")}, "lan0": {netip.MustParseAddr("10.0.0.1")}}
}

func TestForwardMatchEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*ForwardMatch, *EvalContext, map[string][]netip.Addr){
		"disabled":       func(f *ForwardMatch, _ *EvalContext, _ map[string][]netip.Addr) { f.Enabled = false },
		"unbound":        func(f *ForwardMatch, _ *EvalContext, _ map[string][]netip.Addr) { f.IngressDevices = nil },
		"foreign DNAT":   func(_ *ForwardMatch, c *EvalContext, _ map[string][]netip.Addr) { c.Conntrack.Mark = 0 },
		"missing ct":     func(_ *ForwardMatch, c *EvalContext, _ map[string][]netip.Addr) { c.Conntrack = nil },
		"missing device": func(_ *ForwardMatch, c *EvalContext, _ map[string][]netip.Addr) { c.IngressDevice = "" },
		"other device":   func(_ *ForwardMatch, c *EvalContext, _ map[string][]netip.Addr) { c.IngressDevice = "lan0" },
		"address removed": func(_ *ForwardMatch, _ *EvalContext, local map[string][]netip.Addr) {
			local["wan0"] = local["wan0"][:1]
		},
		"only other device local": func(_ *ForwardMatch, _ *EvalContext, local map[string][]netip.Addr) {
			local["lan0"] = local["wan0"]
			local["wan0"] = nil
		},
		"source restricted": func(_ *ForwardMatch, c *EvalContext, _ map[string][]netip.Addr) {
			c.Conntrack.Original.Source = netip.MustParseAddrPort("192.0.2.1:40000")
		},
		"direct backend": func(_ *ForwardMatch, c *EvalContext, _ map[string][]netip.Addr) {
			c.Conntrack.Original.Destination = c.Conntrack.Reply.Source
		},
		"wrong backend": func(_ *ForwardMatch, c *EvalContext, _ map[string][]netip.Addr) {
			c.Conntrack.Reply.Source = netip.MustParseAddrPort("10.0.0.9:502")
		},
		"wrong service port": func(_ *ForwardMatch, c *EvalContext, _ map[string][]netip.Addr) {
			c.Conntrack.Reply.Source = netip.MustParseAddrPort("10.0.0.8:1502")
		},
		"missing public": func(_ *ForwardMatch, c *EvalContext, _ map[string][]netip.Addr) {
			c.Conntrack.Original.Destination = netip.AddrPort{}
		},
		"wrong listen port": func(f *ForwardMatch, _ *EvalContext, _ map[string][]netip.Addr) { f.ListenPort = 502 },
		"wrong protocol":    func(_ *ForwardMatch, c *EvalContext, _ map[string][]netip.Addr) { c.Proto = "udp" },
		"explicit mismatch": func(f *ForwardMatch, _ *EvalContext, _ map[string][]netip.Addr) {
			f.ListenAddress = netip.MustParseAddr("203.0.113.3")
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, c, local := forwardFixture()
			if !f.Matches(c, local) {
				t.Fatal("positive fixture does not match")
			}
			mutate(&f, &c, local)
			if f.Matches(c, local) {
				t.Fatal("missing or contradictory evidence matched")
			}
		})
	}
	f, c, local := forwardFixture()
	f.ListenAddress = netip.MustParseAddr("203.0.113.2")
	if !f.Matches(c, nil) {
		t.Fatal("explicit listen incorrectly requires device-local lookup")
	}
	f.AllowedSources = nil
	c.Conntrack.Original.Source = netip.MustParseAddrPort("192.0.2.1:0")
	if !f.Matches(c, local) {
		t.Fatal("unrestricted source or valid zero source port rejected")
	}
}

func TestViaUsesCurrentForwardResolver(t *testing.T) {
	f, c, local := forwardFixture()
	via := tcpEntry("via", ActionAllow, "502")
	via.ViaForwards = []string{"unknown", "f"}
	snap := &Snapshot{Default: ActionDeny, ForwardMatches: map[string]ForwardMatch{"f": f}, LocalIPv4ByDevice: local, Firewall: []Entry{via}}
	ev := NewEvaluator(snap)
	if got, winner := ev.EvaluateMessage(c, false); got != ActionAllow || ruleID(winner) != via.ID {
		t.Fatal("resolved via did not admit backend coordinates")
	}
	if got, winner := ev.EvaluateTransport(c, true); got != ActionAllow || ruleID(winner) != via.ID {
		t.Fatal("S2 and S4 via disagree")
	}
	if !ev.AddressScopeMatch(0, c) || !ev.TransportScopeMatch(0, c) {
		t.Fatal("scope omitted via match")
	}
	c.Conntrack.Mark = 0
	if ev.AddressScopeMatch(0, c) || ev.TransportScopeMatch(0, c) {
		t.Fatal("scope ignores via")
	}
	if got, winner := ev.EvaluateMessage(c, false); got != ActionDeny || winner != nil {
		t.Fatal("foreign tuple equality admitted")
	}
	c.Conntrack.Mark = markabi.OwnedForwardCtBit
	for _, matches := range []map[string]ForwardMatch{nil, {"f": {}}, {"f": {Enabled: true}}} {
		snap.ForwardMatches = matches
		if got, winner := NewEvaluator(snap).EvaluateTransport(c, true); got != ActionDeny || winner != nil {
			t.Fatal("unknown/disabled/unbound reference widened to any")
		}
	}
}
