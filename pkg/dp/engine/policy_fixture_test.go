// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"net"
	"net/netip"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// In-process nft fakes have no kernel conntrack table.
func noPolicyMarks(context.Context, uint32, uint32, uint32) (int, error) { return 0, nil }

func (idleCapture) RetireFlushed()              {}
func (*retryCapture) RetireFlushed()            {}
func (*blockingCapture) RetireFlushed()         {}
func (*resetOnQueueStopCapture) RetireFlushed() {}
func (*bindCapture) RetireFlushed()             {}

func policyQueue(client, server net.IP, clientPort, serverPort uint16, reply bool) *capture.QueueMetadata {
	c, _ := netip.AddrFromSlice(client.To4())
	s, _ := netip.AddrFromSlice(server.To4())
	original := capture.QueueTuple{Source: netip.AddrPortFrom(c, clientPort), Destination: netip.AddrPortFrom(s, serverPort), Protocol: 6, HasProtocol: true}
	reverse := capture.QueueTuple{Source: original.Destination, Destination: original.Source, Protocol: 6, HasProtocol: true}
	in, out := "eth1", "eth0"
	if reply {
		in, out = out, in
	}
	return &capture.QueueMetadata{IngressDevice: in, EgressDevice: out,
		Conntrack: &capture.QueueConntrack{Original: original, Reply: reverse, DirectionKnown: true, IsReply: reply, HasMark: true, HasStatus: true}}
}
