// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package opcua

import (
	"encoding/hex"
	"net"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Decoder implements dpi.Decoder for OPC UA Binary visibility.
type Decoder struct{}

func NewDecoder() *Decoder { return &Decoder{} }

func (d *Decoder) Supports(state *flow.State) bool {
	if state == nil {
		return false
	}
	// Proto 6 is TCP.
	if state.Key.Proto != 6 {
		return false
	}
	return state.Key.SrcPort == 4840 || state.Key.DstPort == 4840
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
		"message_type": frame.MessageType,
		"chunk_type":   string(frame.ChunkType),
	}

	// Include raw hex for operator visibility (cap to avoid huge payloads).
	raw := pkt.Payload
	if len(raw) > 512 {
		raw = raw[:512]
	}
	attrs["raw_hex"] = hex.EncodeToString(raw)

	kind := "request"
	if IsSessionMessage(frame.MessageType) {
		kind = "session"
		attrs["is_write"] = false
	} else if frame.MessageType == MsgTypeERR {
		kind = "response"
		attrs["is_write"] = false
	} else if frame.MessageType == MsgTypeMSG {
		if frame.HasService {
			attrs["service"] = ServiceName(frame.ServiceNodeID)
			attrs["is_write"] = IsWriteService(frame.ServiceNodeID)
			// Determine kind from service node ID — responses have even-ish IDs.
			switch frame.ServiceNodeID {
			case ServiceReadResponse, ServiceWriteResponse, ServiceBrowseResponse,
				ServiceCreateSubscriptionResponse, ServicePublishResponse, ServiceCallResponse:
				kind = "response"
			default:
				kind = "request"
			}
		} else {
			attrs["is_write"] = false
		}
	}

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "opcua",
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
		Proto:   6,
		Dir:     flow.DirForward,
	}
}
