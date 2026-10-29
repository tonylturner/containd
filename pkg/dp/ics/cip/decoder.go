// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cip

import (
	"net"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
)

// Decoder implements dpi.StreamDecoder for TCP EtherNet/IP encapsulation on
// port 44818 and dpi.Decoder for UDP: implicit I/O datagrams on port 2222 and
// packet-only encapsulation (ListIdentity and other commands) on port 44818.
type Decoder struct{}

func NewDecoder() *Decoder { return &Decoder{} }

func (d *Decoder) Supports(state *flow.State) bool {
	if state == nil {
		return false
	}
	switch state.Key.Proto {
	case 6: // TCP — explicit messaging on port 44818
		return state.Key.SrcPort == ics.CIPPort || state.Key.DstPort == ics.CIPPort
	case 17: // UDP — implicit I/O on 2222, packet-only encapsulation on 44818
		return state.Key.SrcPort == ics.CIPImplicitPort || state.Key.DstPort == ics.CIPImplicitPort ||
			state.Key.SrcPort == ics.CIPPort || state.Key.DstPort == ics.CIPPort
	default:
		return false
	}
}

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *Decoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{ics.CIPPort}, []uint16{ics.CIPImplicitPort, ics.CIPPort}
}

// cipCommands are EIP commands that carry CIP messages.
var cipCommands = map[uint16]bool{
	0x006F: true, // SendRRData
	0x0070: true, // SendUnitData
}

func (d *Decoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil {
		return nil, nil
	}
	// Every datagram on the I/O port is one bounded frame, so an empty or
	// malformed one is still reported rather than silently skipped.
	if state != nil && state.Key.Proto == 17 && (state.Key.SrcPort == ics.CIPImplicitPort || state.Key.DstPort == ics.CIPImplicitPort) {
		return []dpi.Event{ioEvent(state, pkt.Payload)}, nil
	}
	if len(pkt.Payload) == 0 && (state == nil || state.Key.Proto != 17) {
		return nil, nil
	}
	hdr, err := ParseEIPHeader(pkt.Payload)
	if err != nil {
		return []dpi.Event{malformedEvent(state, pkt.Payload, err)}, nil
	}

	events := encapsulationEvents(state, hdr)
	if len(pkt.Payload) != eipHeaderSize+int(hdr.Length) {
		for _, ev := range events {
			addFinding(ev.Attributes, "cip.encapsulation_length")
			delete(ev.Attributes, "is_write")
			delete(ev.Attributes, "is_control")
		}
	}
	return events, nil
}

func (d *Decoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) {
	return nil, nil
}

// Helper for tests/mocks.
func keyFor(src, dst string, sport, dport uint16, proto uint8) flow.Key {
	return flow.Key{
		SrcIP:   net.ParseIP(src),
		DstIP:   net.ParseIP(dst),
		SrcPort: sport,
		DstPort: dport,
		Proto:   proto,
		Dir:     flow.DirForward,
	}
}
