// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"net"
	"slices"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// entryScope is the zone and address scope of one firewall entry, its
// CIDRs parsed once per applied snapshot so that matching a packet
// allocates nothing. It matches as rules.PreviewMatch does on an entry
// that keeps only the zones, sources and destinations: a listed zone
// matches by name, an address by any listed CIDR that parses, and a side
// that lists CIDRs of which none parses matches nothing.
type entryScope struct {
	srcZones, dstZones []string
	src, dst           addressSide
}

// addressSide is one side's CIDRs; listed records that the entry names
// any, parseable or not.
type addressSide struct {
	listed bool
	nets   []*net.IPNet
}

// entryScopes holds the scope of each entry of a snapshot's firewall, by
// index.
type entryScopes []entryScope

func compileEntryScopes(snap *rules.Snapshot) entryScopes {
	if snap == nil {
		return nil
	}
	out := make(entryScopes, len(snap.Firewall))
	for i := range snap.Firewall {
		entry := &snap.Firewall[i]
		out[i] = entryScope{
			srcZones: entry.SourceZones, dstZones: entry.DestZones,
			src: compileAddressSide(entry.Sources), dst: compileAddressSide(entry.Destinations),
		}
	}
	return out
}

func compileAddressSide(cidrs []string) addressSide {
	side := addressSide{listed: len(cidrs) > 0}
	for _, c := range cidrs {
		if _, network, err := net.ParseCIDR(c); err == nil {
			side.nets = append(side.nets, network)
		}
	}
	return side
}

// holds reports whether the scope of entry i holds ctx's zones and
// addresses.
func (s entryScopes) holds(i int, ctx rules.EvalContext) bool {
	scope := &s[i]
	if len(scope.srcZones) > 0 && !slices.Contains(scope.srcZones, ctx.SrcZone) {
		return false
	}
	if len(scope.dstZones) > 0 && !slices.Contains(scope.dstZones, ctx.DstZone) {
		return false
	}
	return scope.src.holds(ctx.SrcIP) && scope.dst.holds(ctx.DstIP)
}

func (a addressSide) holds(ip net.IP) bool {
	if !a.listed {
		return true
	}
	for _, network := range a.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
