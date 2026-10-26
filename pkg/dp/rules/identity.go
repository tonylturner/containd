// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net"
	"net/netip"
	"sort"
)

// Identity bindings are admin-set source-IP tags. A rule's identities match a
// flow whose opener address is bound to any of them, compared exactly and
// case-sensitively. An unbound opener matches no identity rule, ALLOW or
// DENY, in the userspace evaluator as in nftables.

// BindingAddr parses a binding's address the way bindings are keyed: an
// IPv4-mapped IPv6 address is its IPv4 address, and zones are refused.
func BindingAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// IdentitiesOf returns the identities bound to ip in the snapshot, or nil.
// IdentityBindings must be sorted by address, as compilation leaves them.
func (s *Snapshot) IdentitiesOf(ip net.IP) []string {
	if s == nil || len(s.IdentityBindings) == 0 {
		return nil
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}
	addr = addr.Unmap()
	bindings := s.IdentityBindings
	i := sort.Search(len(bindings), func(i int) bool {
		b, ok := BindingAddr(bindings[i].IP)
		return !ok || b.Compare(addr) >= 0
	})
	if i == len(bindings) {
		return nil
	}
	if b, ok := BindingAddr(bindings[i].IP); !ok || b != addr {
		return nil
	}
	return bindings[i].Identities
}

// matchIdentities matches an entry's identity predicate against the
// identities bound to the flow's opener.
func matchIdentities(entry Entry, ctx EvalContext) bool {
	if !entry.HasIdentityPredicate() {
		return true
	}
	for _, id := range entry.Identities {
		for _, got := range ctx.Identities {
			if id == got {
				return true
			}
		}
	}
	return false
}
