// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cip

import (
	"encoding/hex"
	"net"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Decoder implements dpi.Decoder for CIP/EtherNet/IP visibility.
type Decoder struct{}

func NewDecoder() *Decoder { return &Decoder{} }

func (d *Decoder) Supports(state *flow.State) bool {
	if state == nil {
		return false
	}
	switch state.Key.Proto {
	case 6: // TCP — explicit messaging on port 44818
		return state.Key.SrcPort == 44818 || state.Key.DstPort == 44818
	case 17: // UDP — implicit/IO messaging on port 2222
		return state.Key.SrcPort == 2222 || state.Key.DstPort == 2222
	default:
		return false
	}
}

// cipCommands are EIP commands that carry CIP messages.
var cipCommands = map[uint16]bool{
	0x006F: true, // SendRRData
	0x0070: true, // SendUnitData
}

func (d *Decoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}
	hdr, err := ParseEIPHeader(pkt.Payload)
	if err != nil {
		return nil, nil
	}

	attrs := map[string]any{
		"command":        CommandName(hdr.Command),
		"command_code":   hdr.Command,
		"session_handle": hdr.SessionHandle,
	}

	// For commands that carry CIP messages, extract and classify.
	if cipCommands[hdr.Command] && len(hdr.Data) > 0 {
		cipMsg, cipErr := ParseCIPMessage(hdr.Data)
		if cipErr == nil && cipMsg != nil {
			attrs["service_code"] = cipMsg.ServiceCode
			attrs["service_name"] = cipMsg.ServiceName
			attrs["is_write"] = IsWriteService(cipMsg.ServiceCode)
			attrs["is_control"] = IsControlService(cipMsg.ServiceCode)
			if len(cipMsg.Path) > 0 {
				attrs["cip_path"] = hex.EncodeToString(cipMsg.Path)
			}

			kind := "request"
			if cipMsg.IsResponse {
				kind = "response"
			}

			ev := dpi.Event{
				FlowID:     state.Key.Hash(),
				Proto:      "cip",
				Kind:       kind,
				Attributes: attrs,
				Timestamp:  time.Now().UTC(),
			}
			return []dpi.Event{ev}, nil
		}
	}

	// Non-CIP EIP commands (ListIdentity, RegisterSession, etc.)
	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "cip",
		Kind:       "session",
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
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
