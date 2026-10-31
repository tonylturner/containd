// SPDX-License-Identifier: Apache-2.0
package config

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// legacyOverlapOrder retains historical precedence only where two terminals
// might decide the same packet. Its edges follow the legacy total order, so the
// graph is acyclic. Choosing the earliest authored ready vertex preserves
// independent authored order without changing any legacy verdict or winning ID.
// Effects are not vertices; the caller retains their original slots.
func legacyOverlapOrder(cfg *Config) []int {
	entries := make([]rules.Entry, len(cfg.Firewall.Rules))
	degree := make([]int, len(entries))
	edges := make([][]int, len(entries))
	for i, r := range cfg.Firewall.Rules {
		entries[i] = rules.Entry{ID: r.ID, Action: rules.Action(r.Action)}
		if !entries[i].Action.Decides() {
			degree[i] = -1
		}
	}
	legacy := rules.DecisionOrder(entries)
	for rank, from := range legacy {
		for _, to := range legacy[rank+1:] {
			if !terminalScopesDisjoint(cfg, cfg.Firewall.Rules[from], cfg.Firewall.Rules[to]) {
				edges[from] = append(edges[from], to)
				degree[to]++
			}
		}
	}
	out := make([]int, 0, len(legacy))
	for len(out) < len(legacy) {
		for i, d := range degree {
			if d != 0 {
				continue
			}
			out = append(out, i)
			degree[i] = -1
			for _, to := range edges[i] {
				degree[to]--
			}
			break
		}
	}
	return out
}

// A disjoint dimension suffices for the conjunction. Application, identity and
// schedule predicates deliberately provide no proof: absent or uncertain
// evidence must preserve the historical order.
func terminalScopesDisjoint(cfg *Config, a, b Rule) bool {
	return namesDisjoint(a.SourceZones, b.SourceZones) ||
		namesDisjoint(a.DestZones, b.DestZones) ||
		protocolsDisjoint(a.Protocols, b.Protocols) ||
		prefixesDisjoint(a.Sources, b.Sources) ||
		prefixesDisjoint(a.Destinations, b.Destinations) ||
		forwardReferencesDisjoint(cfg, a.ViaForwards, b.ViaForwards)
}

func namesDisjoint(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 || slices.Contains(a, "") || slices.Contains(b, "") {
		return false
	}
	for _, name := range a {
		if slices.Contains(b, name) {
			return false
		}
	}
	return true
}

func prefixesDisjoint(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for _, left := range a {
		p, ok := scopePrefix(left)
		if !ok {
			return false // Includes unresolved VPN selectors.
		}
		for _, right := range b {
			q, ok := scopePrefix(right)
			if !ok || p.Overlaps(q) {
				return false
			}
		}
	}
	return true
}

func protocolsDisjoint(a, b []Protocol) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for _, left := range a {
		for _, right := range b {
			if !protocolPairDisjoint(left, right) {
				return false
			}
		}
	}
	return true
}

func protocolPairDisjoint(a, b Protocol) bool {
	a.Name = strings.ToLower(strings.TrimSpace(a.Name))
	b.Name = strings.ToLower(strings.TrimSpace(b.Name))
	known := func(name string) bool { return name == "tcp" || name == "udp" || name == "icmp" }
	if !known(a.Name) || !known(b.Name) {
		return false
	}
	if a.Name != b.Name {
		return true
	}
	if a.Port == "" || b.Port == "" || a.Name == "icmp" {
		return false
	}
	alo, ahi, aerr := rules.ParsePortRange(a.Port)
	blo, bhi, berr := rules.ParsePortRange(b.Port)
	return aerr == nil && berr == nil && (ahi < blo || bhi < alo)
}

func forwardReferencesDisjoint(cfg *Config, a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	find := func(id string) (PortForward, bool) {
		for _, f := range cfg.Firewall.NAT.PortForwards {
			if f.ID == id {
				return f, true
			}
		}
		return PortForward{}, false
	}
	for _, left := range a {
		f, found := find(left)
		if !found {
			return false
		}
		for _, right := range b {
			g, found := find(right)
			if !found || !forwardSelectorsDisjoint(f, g) {
				return false
			}
		}
	}
	return true
}

func forwardSelectorsDisjoint(a, b PortForward) bool {
	port := func(f PortForward) int {
		if f.DestPort == 0 {
			return f.ListenPort
		}
		return f.DestPort
	}
	protocolA := Protocol{Name: a.Proto, Port: ""}
	protocolB := Protocol{Name: b.Proto, Port: ""}
	validPort := func(p int) bool { return p > 0 && p <= 65535 }
	if protocolPairDisjoint(protocolA, protocolB) ||
		validPort(a.ListenPort) && validPort(b.ListenPort) && a.ListenPort != b.ListenPort ||
		validPort(port(a)) && validPort(port(b)) && port(a) != port(b) ||
		prefixesDisjoint(a.AllowedSources, b.AllowedSources) {
		return true
	}
	distinctAddresses := func(left, right string) bool {
		p, perr := netip.ParseAddr(strings.TrimSpace(left))
		q, qerr := netip.ParseAddr(strings.TrimSpace(right))
		return perr == nil && qerr == nil && p.Unmap() != q.Unmap()
	}
	// Blank listen addresses depend on live device addresses; different IDs
	// or ingress-zone names alone never prove different connection predicates.
	return distinctAddresses(a.DestIP, b.DestIP) || distinctAddresses(a.ListenAddress, b.ListenAddress)
}
