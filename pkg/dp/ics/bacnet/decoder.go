// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package bacnet

import (
	"encoding/hex"
	"net"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Decoder implements dpi.Decoder for BACnet/IP visibility.
type Decoder struct{}

func NewDecoder() *Decoder { return &Decoder{} }

func (d *Decoder) Supports(state *flow.State) bool {
	if state == nil {
		return false
	}
	// Proto 17 is UDP.
	if state.Key.Proto != 17 {
		return false
	}
	return state.Key.SrcPort == 47808 || state.Key.DstPort == 47808
}

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *Decoder) Ports() (tcpPorts, udpPorts []uint16) {
	return nil, []uint16{47808}
}

func (d *Decoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}
	frame, err := ParseFrame(pkt.Payload)
	if err != nil {
		return nil, nil
	}

	attrs := map[string]any{
		"bvlc_function": frame.BVLCFunction,
		"pdu_type":      frame.PDUType,
	}

	// Include raw hex for operator visibility (cap to avoid huge payloads).
	raw := pkt.Payload
	if len(raw) > 512 {
		raw = raw[:512]
	}
	attrs["raw_hex"] = hex.EncodeToString(raw)

	kind := "request"
	if frame.HasAPDU {
		attrs["service_code"] = frame.ServiceChoice
		attrs["service"] = ServiceName(frame.PDUType, frame.ServiceChoice)
		attrs["is_write"] = IsWriteService(frame.ServiceChoice)

		if IsDiscoveryService(frame.PDUType, frame.ServiceChoice) {
			kind = "discovery"
		} else {
			switch frame.PDUType {
			case PDUSimpleACK, PDUComplexACK, PDUError:
				kind = "response"
			default:
				kind = "request"
			}
		}
	} else {
		attrs["service"] = "bvlc"
		attrs["service_code"] = uint8(0)
		attrs["is_write"] = false
	}

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "bacnet",
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

func (d *Decoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) {
	return nil, nil
}

// Helper for tests/mocks.
func keyFor(src, dst string, sport, dport uint16) flow.Key {
	return flow.Key{
		SrcIP:   net.ParseIP(src),
		DstIP:   net.ParseIP(dst),
		SrcPort: sport,
		DstPort: dport,
		Proto:   17,
		Dir:     flow.DirForward,
	}
}
