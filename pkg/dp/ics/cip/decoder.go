// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cip

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Decoder implements dpi.StreamDecoder for TCP CIP/EtherNet/IP visibility
// and dpi.Decoder for UDP I/O traffic.
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

	return encapsulationEvents(state, hdr), nil
}

// encapsulationEvents is shared by TCP stream framing and packet-only UDP.
func encapsulationEvents(state *flow.State, hdr *EIPHeader) []dpi.Event {
	attrs := map[string]any{
		"enip_command":        CommandName(hdr.Command),
		"enip_command_code":   hdr.Command,
		"enip_session_handle": hdr.SessionHandle,
	}

	if _, known := commandNames[hdr.Command]; !known {
		addFinding(attrs, "cip.unknown_command")
	}
	// For commands that carry CIP messages, extract and classify.
	if cipCommands[hdr.Command] && hdr.Status == 0 {
		itemTypes, item, cpfErr := parseCPF(hdr.Data)
		var cipMsg *CIPMessage
		if len(hdr.Data) >= 8 {
			attrs["cpf_item_types"] = strings.Join(itemTypes, ",")
		}
		if cpfErr != nil || item == nil {
			code := "cip.cpf_layout"
			if errors.Is(cpfErr, ErrTruncated) {
				code = "cip.item_truncated"
			}
			addFinding(attrs, code)
		}
		if item != nil {
			var msgErr error
			cipMsg, msgErr = parseCIPFromItem(item)
			if msgErr != nil {
				code := "cip.message_short"
				if errors.Is(msgErr, ErrPathTruncated) {
					code = "cip.epath_truncated"
				}
				addFinding(attrs, code)
			}
		}
		if cipMsg != nil {
			attrs["service_code"] = cipMsg.ServiceCode
			attrs["service_name"] = cipMsg.ServiceName
			attrs["function_code"] = cipMsg.ServiceCode
			attrs["is_write"] = IsWriteService(cipMsg.ServiceCode)
			attrs["is_control"] = IsControlService(cipMsg.ServiceCode)
			if cipMsg.hasStatus {
				attrs["general_status"] = cipMsg.status
			}
			addPathFields(cipMsg.Path, attrs)

			kind := "request"
			if cipMsg.IsResponse {
				kind = "response"
			}

			// Multiple_Service_Packet: extract service count and emit per-sub-service events.
			if cipMsg.ServiceCode == 0x0A && (!cipMsg.IsResponse || cipMsg.hasStatus && cipMsg.status == 0) {
				if len(cipMsg.Data) >= 2 {
					attrs["multi_service_count"] = binary.LittleEndian.Uint16(cipMsg.Data[0:2])
				}
				subs, stopped := parseMSPServices(cipMsg.Data)
				if stopped {
					addFinding(attrs, "cip.msp_layout")
				}

				parentEv := dpi.Event{
					FlowID:     state.Key.Hash(),
					Proto:      "cip",
					Kind:       kind,
					Attributes: attrs,
					Timestamp:  time.Now().UTC(),
				}

				if len(subs) == 0 {
					return []dpi.Event{parentEv}
				}

				results := make([]dpi.Event, 0, 1+len(subs))
				results = append(results, parentEv)
				now := time.Now().UTC()
				flowID := state.Key.Hash()
				parentCodes, _ := eventfields.Strings(attrs, eventfields.KeyConformance)
				for _, sub := range subs {
					subAttrs := map[string]any{
						"enip_command":        attrs["enip_command"],
						"enip_command_code":   attrs["enip_command_code"],
						"enip_session_handle": attrs["enip_session_handle"],
						"service_code":        sub.ServiceCode,
						"service_name":        sub.ServiceName,
						"function_code":       sub.ServiceCode,
						"is_write":            sub.IsWrite,
						"is_control":          sub.IsControl,
						"msp":                 "true",
					}
					if itemTypes, ok := attrs["cpf_item_types"]; ok {
						subAttrs["cpf_item_types"] = itemTypes
					}
					if sub.hasStatus {
						subAttrs["general_status"] = sub.status
					}
					if len(parentCodes) > 0 {
						subAttrs[eventfields.KeyConformance] = parentCodes
					}
					for _, code := range sub.findings {
						addFinding(subAttrs, code)
					}
					addPathFields(sub.Path, subAttrs)
					// The envelope is uncertain too; do not let an intact
					// MSP wrapper hide incomplete child content from consumers.
					subCodes, _ := eventfields.Strings(subAttrs, eventfields.KeyConformance)
					for _, code := range subCodes {
						addFinding(attrs, code)
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
				return results
			}

			ev := dpi.Event{
				FlowID:     state.Key.Hash(),
				Proto:      "cip",
				Kind:       kind,
				Attributes: attrs,
				Timestamp:  time.Now().UTC(),
			}
			return []dpi.Event{ev}
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
	return []dpi.Event{ev}
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
