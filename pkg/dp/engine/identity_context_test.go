// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
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
		ctx, ok := evalContextFromDPIEvent(snap, &flow.State{Key: key}, pkt, dpi.Event{Proto: "modbus", Kind: "request"}, "", "")
		if !ok || !slices.Equal(ctx.Identities, want) {
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
