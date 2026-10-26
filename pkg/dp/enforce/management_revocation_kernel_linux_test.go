// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestKernelManagementIgnoresRevocations revokes, for a full hour, the
// management client's access to the management listener, the reserved
// management listener and an ordinary local service of this namespace. The
// client still reaches both management listeners, before and after another
// apply; only the ordinary service is refused.
func TestKernelManagementIgnoresRevocations(t *testing.T) {
	lab := newNetnsLab(t, "mgr", 80, 30*time.Second)
	const local, client = "198.18.80.1", "198.18.80.2"
	const mgmt, reserved, service = 18080, 18082, 18081
	for _, port := range []int{mgmt, reserved, service} {
		lab.serveLocal(t, local, port)
	}
	c := NewCompiler()
	c.ManagementReservation = &mgmtpath.Reservation{Device: "mgr0", Local: netip.MustParsePrefix(local + "/24"),
		Sources: []netip.Addr{netip.MustParseAddr(client)}, Port: reserved}
	snap := &rules.Snapshot{Default: rules.ActionDeny, LocalInput: []rules.LocalServiceRule{
		{ID: "auto-allow-mgmt-http", Proto: "tcp", Port: mgmt, Ifaces: []string{"mgr0"}, RecoverUnbound: true},
		{ID: "service", Proto: "tcp", Port: service, Ifaces: []string{"mgr0"}},
	}}
	lab.apply(t, c, snap)
	for _, port := range []int{mgmt, reserved, service} {
		if err := lab.probe(local, port, client); err != nil {
			t.Fatalf("port %d unreachable before revocation: %v", port, err)
		}
		p := strconv.Itoa(port)
		e := conntrack.Entry{Proto: "tcp", Src: client, Dst: local, Sport: "40000", Dport: p,
			ReplySrc: local, ReplyDst: client, ReplySport: p, ReplyDport: "40000"}
		if err := NewNftUpdater("").RevokeConnections(lab.ctx, []conntrack.Entry{e}, "client-service", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	for _, pass := range []string{"revoked", "reapplied"} {
		for _, port := range []int{mgmt, reserved} {
			if err := lab.probe(local, port, client); err != nil {
				t.Fatalf("%s: management port %d refused: %v", pass, port, err)
			}
		}
		if err := lab.probe(local, service, client); err == nil {
			t.Fatalf("%s: revoked service still reachable", pass)
		}
		lab.apply(t, c, snap)
	}
}
