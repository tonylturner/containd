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

	// Parse TPKT header.
	tpkt, tpktPayload, err := ParseTPKT(pkt.Payload)
	if err != nil {
		return nil, nil
	}
	_ = tpkt

	// Parse COTP header.
	cotp, cotpPayload, err := ParseCOTP(tpktPayload)
	if err != nil {
		return nil, nil
	}

	// Include raw hex for operator visibility (cap to avoid huge payloads).
	raw := pkt.Payload
	if len(raw) > 512 {
		raw = raw[:512]
	}
	rawHex := hex.EncodeToString(raw)

	// Handle COTP Connection Request / Connection Confirm as connection events.
	if cotp.PDUType == COTPConnectionRequest || cotp.PDUType == COTPConnectionConfirm {
		attrs := map[string]any{
			"cotp_pdu_type": cotp.PDUType,
			"raw_hex":       rawHex,
		}
		ev := dpi.Event{
			FlowID:     state.Key.Hash(),
			Proto:      "s7comm",
			Kind:       "connection",
			Attributes: attrs,
			Timestamp:  time.Now().UTC(),
		}
		return []dpi.Event{ev}, nil
	}

	// Only process COTP Data Transfer (DT) PDUs for S7comm.
	if cotp.PDUType != COTPData {
		return nil, nil
	}

	// Parse S7comm header.
	s7hdr, err := ParseS7Header(cotpPayload)
	if err != nil {
		return nil, nil
	}

	// Determine event kind based on message type.
	kind := "request"
	switch s7hdr.MessageType {
	case MsgTypeJob:
		kind = "request"
	case MsgTypeAck, MsgTypeAckData:
		kind = "response"
	case MsgTypeUserdata:
		kind = "request"
	}

	attrs := map[string]any{
		"message_type":  s7hdr.MessageType,
		"pdu_reference": s7hdr.PDUReference,
		"raw_hex":       rawHex,
	}

	// Extract function code from parameter block if available.
	if fc, ok := S7ParamFunctionCode(cotpPayload, s7hdr); ok {
		attrs["function_code"] = fc
		attrs["function_name"] = FunctionCodeName(fc)
		attrs["is_write"] = IsWriteFunctionCode(fc)
		attrs["is_control"] = IsControlFunctionCode(fc)
	}

	// Include error fields for Ack-Data messages.
	if s7hdr.MessageType == MsgTypeAckData {
		attrs["error_class"] = s7hdr.ErrorClass
		attrs["error_code"] = s7hdr.ErrorCode
	}

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "s7comm",
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
