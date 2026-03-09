// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cip

import (
	"encoding/binary"
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

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *Decoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{44818}, []uint16{2222}
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
			attrs["function_code"] = cipMsg.ServiceCode
			attrs["is_write"] = IsWriteService(cipMsg.ServiceCode)
			attrs["is_control"] = IsControlService(cipMsg.ServiceCode)
			if len(cipMsg.Path) > 0 {
				attrs["cip_path"] = hex.EncodeToString(cipMsg.Path)
				ep := ParseEPath(cipMsg.Path)
				if ep.ClassID != 0 {
					attrs["object_class"] = ep.ClassID
					attrs["object_class_name"] = ObjectClassName(ep.ClassID)
				}
				attrs["instance_id"] = ep.InstanceID
				attrs["attribute_id"] = ep.AttributeID
				attrs["address"] = FormatAddress(ep)
			}

			kind := "request"
			if cipMsg.IsResponse {
				kind = "response"
			}

			// Multiple_Service_Packet: extract service count and emit per-sub-service events.
			if cipMsg.ServiceCode == 0x0A && len(cipMsg.Data) >= 2 {
				svcCount := binary.LittleEndian.Uint16(cipMsg.Data[0:2])
				attrs["multi_service_count"] = svcCount

				parentEv := dpi.Event{
					FlowID:     state.Key.Hash(),
					Proto:      "cip",
					Kind:       kind,
					Attributes: attrs,
					Timestamp:  time.Now().UTC(),
				}

				subs := ParseMSPServices(cipMsg.Data)
				if len(subs) == 0 {
					return []dpi.Event{parentEv}, nil
				}

				results := make([]dpi.Event, 0, 1+len(subs))
				results = append(results, parentEv)
				now := time.Now().UTC()
				flowID := state.Key.Hash()
				for _, sub := range subs {
					subAttrs := map[string]any{
						"command":        attrs["command"],
						"command_code":   attrs["command_code"],
						"session_handle": attrs["session_handle"],
						"service_code":   sub.ServiceCode,
						"service_name":   sub.ServiceName,
						"function_code":  sub.ServiceCode,
						"is_write":       sub.IsWrite,
						"is_control":     sub.IsControl,
						"msp":            "true",
					}
					if len(sub.Path) > 0 {
						subAttrs["cip_path"] = hex.EncodeToString(sub.Path)
						ep := ParseEPath(sub.Path)
						if ep.ClassID != 0 {
							subAttrs["object_class"] = ep.ClassID
							subAttrs["object_class_name"] = ObjectClassName(ep.ClassID)
						}
						subAttrs["instance_id"] = ep.InstanceID
						subAttrs["attribute_id"] = ep.AttributeID
						subAttrs["address"] = FormatAddress(ep)
					}
					subKind := kind
					results = append(results, dpi.Event{
						FlowID:     flowID,
						Proto:      "cip",
						Kind:       subKind,
						Attributes: subAttrs,
						Timestamp:  now,
					})
				}
				return results, nil
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
