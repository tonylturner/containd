// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package rules

import (
	"net"
	"slices"
	"testing"
)

// scopeEntries cover listed and empty sides, CIDRs that net.ParseCIDR
// refuses (bare addresses, ranges, junk), both families, and zones.
func scopeEntries() []Entry {
	cidrs := [][]string{
		nil,
		{"10.0.0.0/8"},
		{"10.0.0.5"},
		{"10.0.0.5", "192.168.1.0/24"},
		{"not-a-cidr", "10.0.0.1-10.0.0.9"},
		{"2001:db8::/32"},
		{"::ffff:10.0.0.0/104"},
		{"0.0.0.0/0", "::/0"},
	}
	zones := [][]string{nil, {"plant"}, {"control", "plant"}, {""}}
	var out []Entry
	for _, src := range cidrs {
		for _, dst := range cidrs {
			out = append(out, Entry{Sources: src, Destinations: dst})
		}
	}
	for _, sz := range zones {
		for _, dz := range zones {
			out = append(out, Entry{SourceZones: sz, DestZones: dz, Sources: []string{"10.0.0.0/8"}})
		}
	}
	return out
}

func scopeContexts() []EvalContext {
	ips := []net.IP{nil, net.ParseIP("10.0.0.5"), net.ParseIP("192.168.1.7"), net.ParseIP("172.16.0.1"),
		net.ParseIP("2001:db8::5"), net.ParseIP("::ffff:10.0.0.5"), net.IPv4(10, 0, 0, 5).To4()}
	zones := []string{"", "plant", "control", "dmz"}
	var out []EvalContext
	for _, src := range ips {
		for _, dst := range ips {
			for _, sz := range zones {
				for _, dz := range zones {
					out = append(out, EvalContext{SrcIP: src, DstIP: dst, SrcZone: sz, DstZone: dz})
				}
			}
		}
	}
	return out
}

// inCIDRs is the reference: each CIDR parsed at lookup, those that do not
// parse skipped.
func inCIDRs(ip net.IP, cidrs []string) bool {
	for _, c := range cidrs {
		if _, network, err := net.ParseCIDR(c); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func referenceScope(entry Entry, ctx EvalContext) bool {
	return (len(entry.SourceZones) == 0 || slices.Contains(entry.SourceZones, ctx.SrcZone)) &&
		(len(entry.DestZones) == 0 || slices.Contains(entry.DestZones, ctx.DstZone)) &&
		(len(entry.Sources) == 0 || inCIDRs(ctx.SrcIP, entry.Sources)) &&
		(len(entry.Destinations) == 0 || inCIDRs(ctx.DstIP, entry.Destinations))
}

// TestAddressScopeMatchParsesOnce checks that the networks compiled with
// the snapshot decide as parsing every CIDR at each lookup does, and that
// the Evaluator and PreviewMatch decide the same.
func TestAddressScopeMatchParsesOnce(t *testing.T) {
	snap := &Snapshot{Firewall: scopeEntries()}
	ev := NewEvaluator(snap)
	held := 0
	for i, entry := range snap.Firewall {
		for _, ctx := range scopeContexts() {
			want := referenceScope(entry, ctx)
			if got := ev.AddressScopeMatch(i, ctx); got != want {
				t.Fatalf("entry %+v ctx %+v: AddressScopeMatch = %v, want %v", entry, ctx, got, want)
			}
			if got := PreviewMatch(entry, ctx); got != want {
				t.Fatalf("entry %+v ctx %+v: PreviewMatch = %v, want %v", entry, ctx, got, want)
			}
			single := NewEvaluator(&Snapshot{Firewall: []Entry{entry}})
			if got := single.AnyMatch(ctx) != nil; got != want {
				t.Fatalf("entry %+v ctx %+v: AnyMatch = %v, want %v", entry, ctx, got, want)
			}
			if want {
				held++
			}
		}
	}
	if held == 0 {
		t.Fatal("no context is held: the comparison proves nothing")
	}
}

// TestMatchingAllocatesNothing checks that deciding a packet against a
// compiled snapshot does not allocate.
func TestMatchingAllocatesNothing(t *testing.T) {
	const n = 16
	ev := NewEvaluator(benchPolicy(n))
	ctx := benchContext(n)
	if allocs := testing.AllocsPerRun(100, func() {
		if _, entry := ev.EvaluateMatch(ctx); entry == nil {
			t.Fatal("no rule matched")
		}
	}); allocs != 0 {
		t.Fatalf("EvaluateMatch allocates %v times per call", allocs)
	}
	if allocs := testing.AllocsPerRun(100, func() {
		if !ev.AddressScopeMatch(n-1, ctx) {
			t.Fatal("flow out of scope")
		}
	}); allocs != 0 {
		t.Fatalf("AddressScopeMatch allocates %v times per call", allocs)
	}
}
