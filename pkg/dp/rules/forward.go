// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"net/netip"
	"slices"

	"github.com/tonylturner/containd/pkg/dp/markabi"
)

// ForwardMatch is a resolved current translation selector. An invalid
// ListenAddress means the original destination must be local to the ingress
// device. Backend includes the effective (possibly inherited) service port.
// The Snapshot map key is the forward ID; disabled or unbound entries never match.
type ForwardMatch struct {
	Enabled        bool
	IngressDevices []string
	Protocol       string
	ListenAddress  netip.Addr
	ListenPort     uint16
	AllowedSources []netip.Prefix
	Backend        netip.AddrPort
}

// ConnectionTuple is one conntrack tuple, not a packet-direction inference.
// Invalid address/port values represent missing dependent evidence. A valid
// address/port with port zero is distinct from an invalid value.
type ConnectionTuple struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

// ConntrackContext is verified conntrack evidence. A nil context denotes
// missing/invalid/untracked metadata. Original and Reply retain kernel
// orientation even when the captured packet travels in the reply direction.
type ConntrackContext struct {
	Mark     uint32
	Original ConnectionTuple
	Reply    ConnectionTuple
}

// Matches applies the same current selector to original/public and backend
// coordinates in either packet direction. IngressDevice is original ingress,
// never the reply packet's ingress. No tuple equality can establish ownership.
func (f ForwardMatch) Matches(ctx EvalContext, localIPv4ByDevice map[string][]netip.Addr) bool {
	ct := ctx.Conntrack
	if !f.Enabled || ct == nil || ct.Mark&markabi.OwnedForwardCtBit == 0 ||
		ctx.IngressDevice == "" || !slices.Contains(f.IngressDevices, ctx.IngressDevice) ||
		(f.Protocol != "tcp" && f.Protocol != "udp") || ctx.Proto != f.Protocol ||
		!f.Backend.IsValid() || !f.Backend.Addr().Is4() || f.Backend.Port() == 0 ||
		ct.Reply.Source != f.Backend || f.ListenPort == 0 {
		return false
	}
	public, client := ct.Original.Destination, ct.Original.Source
	if !public.IsValid() || !public.Addr().Is4() || public.Port() != f.ListenPort ||
		!client.IsValid() || !client.Addr().Is4() {
		return false
	}
	if f.ListenAddress.IsValid() {
		if public.Addr() != f.ListenAddress {
			return false
		}
	} else if !slices.Contains(localIPv4ByDevice[ctx.IngressDevice], public.Addr()) {
		return false
	}
	if len(f.AllowedSources) == 0 {
		return true
	}
	for _, source := range f.AllowedSources {
		if source.Contains(client.Addr()) {
			return true
		}
	}
	return false
}

func (ce *compiledEntry) matchVia(ctx EvalContext) bool {
	if len(ce.ViaForwards) == 0 {
		return true
	}
	for _, id := range ce.ViaForwards {
		if f, ok := ce.forwardMatches[id]; ok && f.Matches(ctx, ce.localIPv4ByDevice) {
			return true
		}
	}
	return false
}
