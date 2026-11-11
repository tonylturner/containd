// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestStreamTransportRoleRequiresAuthority(t *testing.T) {
	e := recordEngine(t)
	p := recordPacket(100, capture.TCPFlagACK, "")
	st := e.trackFlow(p, time.Now())
	if got := e.streamTransportRole(st, p); got != dpi.DirUnknown {
		t.Fatalf("arrival order became authority: %v", got)
	}
	e = recordEngine(t)
	p.TCP.Flags = capture.TCPFlagSYN
	st = e.trackFlow(p, time.Now())
	if got := e.streamTransportRole(st, p); got != dpi.ClientToServer {
		t.Fatal(got)
	}
	p.TCP.Flags = capture.TCPFlagACK
	if got := e.streamTransportRole(st, p); got != dpi.ClientToServer {
		t.Fatalf("lost observed opener: %v", got)
	}
	reply := p
	reply.SrcIP, reply.DstIP, reply.SrcPort, reply.DstPort = p.DstIP, p.SrcIP, p.DstPort, p.SrcPort
	server := e.trackFlow(reply, time.Now())
	if server.Key.Dir != flow.DirReverse || e.streamTransportRole(server, reply) != dpi.ServerToClient {
		t.Fatal("reply did not inherit the observed opener")
	}
}
