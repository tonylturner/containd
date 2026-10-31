// SPDX-License-Identifier: Apache-2.0
package config

import (
	"net/netip"
	"strings"
)

// scopePrefix follows net.IPNet.Contains, the evaluator's CIDR matcher.
// Mapped IPv4 prefixes with at least 96 prefix bits match IPv4 addresses;
// their different spelling must never prove transport scopes disjoint.
func scopePrefix(raw string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, false
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}
