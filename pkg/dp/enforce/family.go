// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// A rule's addresses are lowered per address family: nft matches IPv4
// addresses with ip and IPv6 addresses with ip6, never both in one line.
// Families are numbered as identityFamilies: 0 is IPv4, 1 IPv6.
const familyAny = -1

// familyKeyword is the nft payload keyword of each family's addresses.
var familyKeyword = [2]string{"ip", "ip6"}

// addrScope is the part of a rule's address match in one family.
type addrScope struct {
	family  int // 0, 1, or familyAny for a rule without addresses
	sources []string
	dests   []string
}

// addrScopes splits e's addresses by family. A rule without addresses has
// one scope of familyAny. Otherwise each family gets a scope when every
// side with addresses has one in that family (a side without addresses
// matches any); a rule whose sources and destinations share no family has
// none, and matches nothing.
func addrScopes(e rules.Entry) ([]addrScope, error) {
	if len(e.Sources) == 0 && len(e.Destinations) == 0 {
		return []addrScope{{family: familyAny}}, nil
	}
	srcs, err := splitFamilies(e.Sources)
	if err != nil {
		return nil, fmt.Errorf("entry %s sources: %w", e.ID, err)
	}
	dsts, err := splitFamilies(e.Destinations)
	if err != nil {
		return nil, fmt.Errorf("entry %s destinations: %w", e.ID, err)
	}
	var out []addrScope
	for f := range familyKeyword {
		if (len(e.Sources) > 0 && len(srcs[f]) == 0) || (len(e.Destinations) > 0 && len(dsts[f]) == 0) {
			continue
		}
		out = append(out, addrScope{family: f, sources: srcs[f], dests: dsts[f]})
	}
	return out, nil
}

// splitFamilies parses addresses and prefixes, in nft's notation, by
// family. Anything else is refused, so nothing but an address reaches nft.
func splitFamilies(list []string) ([2][]string, error) {
	var out [2][]string
	for _, raw := range list {
		s := strings.TrimSpace(raw)
		var addr netip.Addr
		text := ""
		if p, err := netip.ParsePrefix(s); err == nil {
			addr, text = p.Addr(), p.String()
		} else if a, err := netip.ParseAddr(s); err == nil {
			addr, text = a, a.String()
		} else {
			return out, fmt.Errorf("invalid address %q: must be an IP address or CIDR", raw)
		}
		if addr.Zone() != "" {
			return out, fmt.Errorf("invalid address %q: zoned addresses are not allowed", raw)
		}
		f := 0
		if addr.Is6() {
			f = 1
		}
		out[f] = append(out[f], text)
	}
	return out, nil
}

// entryFamilies reports the families e's addresses can match. An entry
// whose addresses do not parse matches none: it fails to compile.
func entryFamilies(e rules.Entry) [2]bool {
	var out [2]bool
	scopes, err := addrScopes(e)
	if err != nil {
		return out
	}
	for _, s := range scopes {
		if s.family == familyAny {
			return [2]bool{true, true}
		}
		out[s.family] = true
	}
	return out
}

// header matches the scope's addresses in a packet's header; swap matches
// the destinations as sources and the sources as destinations.
func (s addrScope) header(swap bool) []string {
	if s.family == familyAny {
		return nil
	}
	src, dst := s.sources, s.dests
	if swap {
		src, dst = dst, src
	}
	ip := familyKeyword[s.family]
	var out []string
	if len(src) > 0 {
		out = append(out, ip+" saddr { "+strings.Join(src, ", ")+" }")
	}
	if len(dst) > 0 {
		out = append(out, ip+" daddr { "+strings.Join(dst, ", ")+" }")
	}
	return out
}

// conntrack matches the scope's addresses against a connection's original
// tuple as the forward chain saw its first packet, for packets of either
// direction: the opener's address, and the server's address after DNAT
// (the reply's source).
func (s addrScope) conntrack() []string {
	if s.family == familyAny {
		return nil
	}
	ip := familyKeyword[s.family]
	var out []string
	if len(s.sources) > 0 {
		out = append(out, "ct original "+ip+" saddr { "+strings.Join(s.sources, ", ")+" }")
	}
	if len(s.dests) > 0 {
		out = append(out, "ct reply "+ip+" saddr { "+strings.Join(s.dests, ", ")+" }")
	}
	return out
}

// familyWarnings reports the firewall rules whose sources and destinations
// share no address family: such a rule matches nothing.
func familyWarnings(snap *rules.Snapshot) []RuleWarning {
	var out []RuleWarning
	for _, e := range snap.Firewall {
		if scopes, err := addrScopes(e); err == nil && len(scopes) == 0 {
			out = append(out, RuleWarning{RuleID: e.ID, Predicate: PredicateAddressFamily, Action: e.Action,
				Message: "its sources and destinations share no address family (IPv4 or IPv6); the rule matches nothing"})
		}
	}
	return out
}
