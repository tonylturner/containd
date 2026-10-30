// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestEvalContextsCarryOpenerIdentities: generic ICS and IEC 104 contexts
// carry the identities bound to the connection's opener, in both
// directions.
func TestEvalContextsCarryOpenerIdentities(t *testing.T) {
	snap := &rules.Snapshot{IdentityBindings: []rules.IdentityBinding{{IP: testClient, Identities: []string{"operator"}}}}
	want := []string{"operator"}
	for _, dir := range []flow.Direction{flow.DirForward, flow.DirReverse} {
		key := flow.Key{SrcIP: net.ParseIP(testClient), DstIP: net.ParseIP(testServer), SrcPort: 40000, DstPort: 502, Proto: 6, Dir: dir}
		if dir == flow.DirReverse {
			key = flow.Key{SrcIP: net.ParseIP(testServer), DstIP: net.ParseIP(testClient), SrcPort: 502, DstPort: 40000, Proto: 6, Dir: dir}
		}
		pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: key.SrcPort, DstPort: key.DstPort}
		ctx := singleEvalContext(t, snap, &flow.State{Key: key}, pkt, dpi.Event{Proto: "modbus", Kind: "request"}, "", "")
		if !slices.Equal(ctx.Identities, want) {
			t.Fatalf("direction %v: identities %v, want %v", dir, ctx.Identities, want)
		}
	}
	client := netip.AddrPortFrom(netip.MustParseAddr(testClient), 40000)
	server := netip.AddrPortFrom(netip.MustParseAddr(testServer), iec104Port)
	none := func(*rules.Snapshot, net.IP, net.IP) (string, string) { return "", "" }
	if ctx := iecSessionContext(snap, client, server, none); !slices.Equal(ctx.Identities, want) {
		t.Fatalf("IEC 104 session identities %v, want %v", ctx.Identities, want)
	}
	if ctx := iecSessionContext(snap, server, client, none); ctx.Identities != nil {
		t.Fatalf("unbound opener carries identities %v", ctx.Identities)
	}
}

// TestTagsFollowOpenerIdentities: a TAG rule with identities labels the
// connections, flow states and IEC 104 session events whose opener is bound
// to one of them, as nftables counts them.
func TestTagsFollowOpenerIdentities(t *testing.T) {
	snap := rules.Snapshot{
		Default:          rules.ActionDeny,
		IdentityBindings: []rules.IdentityBinding{{IP: testClient, Identities: []string{"operator"}}},
		Firewall:         []rules.Entry{tagEntry("tag-ops", "ops", func(e *rules.Entry) { e.Identities = []string{"operator"} })},
	}
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	e.LoadRules(snap)
	got := e.TagConnections([]conntrack.Entry{
		{Proto: "tcp", Src: testClient, Dst: testServer, Sport: "41000", Dport: "502"},
		{Proto: "tcp", Src: testServer, Dst: testClient, Sport: "41000", Dport: "502"},
	})
	if !slices.Equal(got[0].Tags, []string{"ops"}) || got[1].Tags != nil {
		t.Fatalf("connection tags = %v, %v; want [ops] for the bound opener only", got[0].Tags, got[1].Tags)
	}
	reply := flow.Key{SrcIP: net.ParseIP(testServer), DstIP: net.ParseIP(testClient), SrcPort: 502, DstPort: 41000, Proto: 6, Dir: flow.DirReverse}
	if tags := e.flowTags(&flow.State{Key: reply}); !slices.Equal(tags, []string{"ops"}) {
		t.Fatalf("reply flow tags = %v, want the opener's [ops]", tags)
	}
	table := newIECTable("enforce", &zoneCache{})
	table.snap, table.policy = &snap, rules.NewEvaluator(&snap)
	evs := table.withSessionTags([]iecTelemetry{{Event: events.Event{SrcIP: testClient, DstIP: testServer, DstPort: iec104Port, Transport: "tcp"}}})
	if got := evs[0].Attributes[events.KeyTags]; !reflect.DeepEqual(got, []string{"ops"}) {
		t.Fatalf("IEC 104 session tags = %v, want [ops]", got)
	}
}
