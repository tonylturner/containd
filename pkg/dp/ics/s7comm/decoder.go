// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package s7comm

import (
	"encoding/hex"
	"net"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Decoder implements dpi.Decoder for S7comm (Siemens S7) visibility.
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
	return state.Key.SrcPort == 102 || state.Key.DstPort == 102
}

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *Decoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{102}, nil
}

func (d *Decoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}

	s7hdr, cotp, cotpPayload, rawHex, err := parseS7Packet(pkt.Payload)
	if err != nil {
		return nil, nil
	}

	// Handle COTP Connection Request / Connection Confirm as connection events.
	if cotp.PDUType == COTPConnectionRequest || cotp.PDUType == COTPConnectionConfirm {
		return []dpi.Event{newS7ConnectionEvent(state, cotp, rawHex)}, nil
	}

	// Only process COTP Data Transfer (DT) PDUs for S7comm.
	if cotp.PDUType != COTPData {
		return nil, nil
	}

	return []dpi.Event{newS7DataEvent(state, s7hdr, cotpPayload, rawHex)}, nil
}

func parseS7Packet(payload []byte) (*S7Header, *COTPHeader, []byte, string, error) {
	tpkt, tpktPayload, err := ParseTPKT(payload)
	if err != nil {
		return nil, nil, nil, "", err
	}
	_ = tpkt
	cotp, cotpPayload, err := ParseCOTP(tpktPayload)
	if err != nil {
		return nil, nil, nil, "", err
	}
	s7hdr, err := ParseS7Header(cotpPayload)
	if err != nil && cotp.PDUType == COTPData {
		return nil, nil, nil, "", err
	}
	return s7hdr, cotp, cotpPayload, cappedS7RawHex(payload), nil
}

func cappedS7RawHex(payload []byte) string {
	raw := payload
	if len(raw) > 512 {
		raw = raw[:512]
	}
	return hex.EncodeToString(raw)
}

func newS7ConnectionEvent(state *flow.State, cotp *COTPHeader, rawHex string) dpi.Event {
	return dpi.Event{
		FlowID: state.Key.Hash(),
		Proto:  "s7comm",
		Kind:   "connection",
		Attributes: map[string]any{
			"cotp_pdu_type": cotp.PDUType,
			"raw_hex":       rawHex,
		},
		Timestamp: time.Now().UTC(),
	}
}

func newS7DataEvent(state *flow.State, s7hdr *S7Header, cotpPayload []byte, rawHex string) dpi.Event {
	attrs := map[string]any{
		"message_type":  s7hdr.MessageType,
		"pdu_reference": s7hdr.PDUReference,
		"raw_hex":       rawHex,
	}
	addS7FunctionAttrs(attrs, cotpPayload, s7hdr)
	addS7AckAttrs(attrs, s7hdr)
	return dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "s7comm",
		Kind:       s7MessageKind(s7hdr),
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
}

func s7MessageKind(s7hdr *S7Header) string {
	switch s7hdr.MessageType {
	case MsgTypeAck, MsgTypeAckData:
		return "response"
	default:
		return "request"
	}
}

func addS7FunctionAttrs(attrs map[string]any, cotpPayload []byte, s7hdr *S7Header) {
	fc, ok := S7ParamFunctionCode(cotpPayload, s7hdr)
	if !ok {
		return
	}
	attrs["function_code"] = fc
	attrs["function_name"] = FunctionCodeName(fc)
	attrs["is_write"] = IsWriteFunctionCode(fc)
	attrs["is_control"] = IsControlFunctionCode(fc)
	if fc == FuncReadVar || fc == FuncWriteVar {
		addS7VariableAttrs(attrs, cotpPayload, s7hdr, fc)
	}
}

func addS7VariableAttrs(attrs map[string]any, cotpPayload []byte, s7hdr *S7Header, fc byte) {
	items, itemCount := ParseS7VarItems(cotpPayload, s7hdr)
	if itemCount > 0 {
		attrs["item_count"] = itemCount
	}
	if len(items) == 0 {
		return
	}
	first := items[0]
	attrs["area"] = AreaName(first.Area)
	attrs["address"] = FormatAddress(first.Address)
	if first.Area == AreaDataBlocks {
		attrs["db_number"] = first.DBNumber
	}
	if fc == FuncWriteVar && first.Area == AreaDataBlocks {
		attrs["safety_critical"] = true
	}
}

func addS7AckAttrs(attrs map[string]any, s7hdr *S7Header) {
	if s7hdr.MessageType != MsgTypeAckData {
		return
	}
	attrs["error_class"] = s7hdr.ErrorClass
	attrs["error_code"] = s7hdr.ErrorCode
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
