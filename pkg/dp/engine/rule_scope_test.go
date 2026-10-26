// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"net"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// scopeEntries cover listed and empty sides, CIDRs that net.ParseCIDR
// refuses (bare addresses, ranges, junk), both families, and zones.
func scopeEntries() []rules.Entry {
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
	var out []rules.Entry
	for _, src := range cidrs {
		for _, dst := range cidrs {
			out = append(out, rules.Entry{Sources: src, Destinations: dst})
		}
	}
	for _, sz := range zones {
		for _, dz := range zones {
			out = append(out, rules.Entry{SourceZones: sz, DestZones: dz, Sources: []string{"10.0.0.0/8"}})
		}
	}
	return out
}

func scopeContexts() []rules.EvalContext {
	ips := []net.IP{nil, net.ParseIP("10.0.0.5"), net.ParseIP("192.168.1.7"), net.ParseIP("172.16.0.1"),
		net.ParseIP("2001:db8::5"), net.ParseIP("::ffff:10.0.0.5"), net.IPv4(10, 0, 0, 5).To4()}
	zones := []string{"", "plant", "control", "dmz"}
	var out []rules.EvalContext
	for _, src := range ips {
		for _, dst := range ips {
			for _, sz := range zones {
				for _, dz := range zones {
					out = append(out, rules.EvalContext{SrcIP: src, DstIP: dst, SrcZone: sz, DstZone: dz})
				}
			}
		}
	}
	return out
}

// TestEntryScopesMatchPreviewMatch checks that a precompiled scope decides
// as rules.PreviewMatch does on the entry's zones and addresses alone, the
// scope test fail-closed inspection applies to each packet.
func TestEntryScopesMatchPreviewMatch(t *testing.T) {
	snap := &rules.Snapshot{Firewall: scopeEntries()}
	scopes := compileEntryScopes(snap)
	held := 0
	for i, entry := range snap.Firewall {
		scope := rules.Entry{SourceZones: entry.SourceZones, DestZones: entry.DestZones,
			Sources: entry.Sources, Destinations: entry.Destinations}
		for _, ctx := range scopeContexts() {
			want := rules.PreviewMatch(scope, ctx)
			if got := scopes.holds(i, ctx); got != want {
				t.Fatalf("entry %+v ctx %+v: holds = %v, PreviewMatch = %v", entry, ctx, got, want)
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

// TestEntryScopesFollowTheAppliedSnapshot checks that each stored snapshot
// is published with its own scopes.
func TestEntryScopesFollowTheAppliedSnapshot(t *testing.T) {
	var r ruleSnapshots
	if snap, scopes := r.LoadScoped(); snap != nil || scopes != nil {
		t.Fatalf("empty store = %v, %v", snap, scopes)
	}
	ctx := rules.EvalContext{SrcIP: net.ParseIP("10.0.0.5"), DstIP: net.ParseIP("10.1.0.5")}
	for _, cidr := range []string{"10.0.0.0/24", "192.168.0.0/16"} {
		r.Store(&rules.Snapshot{Firewall: []rules.Entry{{Sources: []string{cidr}}}})
		snap, scopes := r.LoadScoped()
		if snap != r.Load() || len(scopes) != 1 || scopes.holds(0, ctx) != (cidr == "10.0.0.0/24") {
			t.Fatalf("scopes of the snapshot with %s do not follow it", cidr)
		}
	}
}

func TestEntryScopesAllocateNothing(t *testing.T) {
	scopes := compileEntryScopes(&rules.Snapshot{Firewall: []rules.Entry{
		{SourceZones: []string{"control"}, Sources: []string{"10.9.0.0/16", "10.0.0.0/8"}, Destinations: []string{"2001:db8::/32", "10.1.0.0/16"}},
	}})
	ctx := rules.EvalContext{SrcZone: "control", SrcIP: net.ParseIP("10.0.0.5"), DstIP: net.ParseIP("10.1.0.5")}
	if allocs := testing.AllocsPerRun(100, func() {
		if !scopes.holds(0, ctx) {
			t.Fatal("flow out of scope")
		}
	}); allocs != 0 {
		t.Fatalf("holds allocates %v times per call", allocs)
	}
}
