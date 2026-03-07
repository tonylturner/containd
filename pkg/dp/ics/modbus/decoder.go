// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package modbus

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Decoder implements dpi.Decoder for Modbus/TCP visibility.
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
	return state.Key.SrcPort == 502 || state.Key.DstPort == 502
}

func (d *Decoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}
	frame, err := ParseTCPFrame(pkt.Payload)
	if err != nil {
		return nil, nil
	}
	attrs := map[string]any{
		"transaction_id": frame.TransactionID,
		"unit_id":        frame.UnitID,
		"function_code":  frame.FunctionCode,
		"is_write":       IsWriteFunctionCode(frame.FunctionCode),
	}
	// Include raw hex for operator visibility (cap to avoid huge payloads).
	raw := pkt.Payload
	if len(raw) > 512 {
		raw = raw[:512]
	}
	attrs["raw_hex"] = hex.EncodeToString(raw)
	// Best-effort parse for common request fields (address/quantity).
	if len(frame.PDU) >= 4 {
		addr := binary.BigEndian.Uint16(frame.PDU[0:2])
		qty := binary.BigEndian.Uint16(frame.PDU[2:4])
		attrs["address"] = addr
		attrs["quantity"] = qty
	}
	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "modbus",
		Kind:       "request",
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
