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

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *Decoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{502}, nil
}

func (d *Decoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}
	frame, err := ParseTCPFrame(pkt.Payload)
	if err != nil {
		return nil, nil
	}
	fc := frame.FunctionCode
	isException := fc >= 128

	attrs := map[string]any{
		"transaction_id": frame.TransactionID,
		"unit_id":        frame.UnitID,
		"function_code":  fc,
	}

	kind := "request"

	if isException {
		kind = "exception"
		baseFc := fc - 128
		attrs["function_code"] = baseFc
		attrs["is_write"] = IsWriteFunctionCode(baseFc)
		if len(frame.PDU) >= 1 {
			ec := frame.PDU[0]
			attrs["exception_code"] = ec
			attrs["exception_description"] = exceptionName(ec)
		}
	} else {
		attrs["is_write"] = IsWriteFunctionCode(fc)

		switch fc {
		case 8: // Diagnostics — sub-function is first 2 bytes of PDU.
			if len(frame.PDU) >= 2 {
				sub := binary.BigEndian.Uint16(frame.PDU[0:2])
				attrs["sub_function"] = sub
				attrs["sub_function_name"] = diagSubFunctionName(sub)
				// Sub-functions 1 (restart comm) and 4 (force listen only) are writes.
				if sub == 1 || sub == 4 {
					attrs["is_write"] = true
				}
			}
		case 43: // MEI (Encapsulated Interface Transport).
			if len(frame.PDU) >= 1 {
				mei := frame.PDU[0]
				attrs["mei_type"] = mei
				if mei == 14 {
					attrs["mei_type_name"] = "read_device_identification"
				}
			}
		default:
			// Best-effort parse for common request fields (address/quantity).
			if len(frame.PDU) >= 4 {
				addr := binary.BigEndian.Uint16(frame.PDU[0:2])
				qty := binary.BigEndian.Uint16(frame.PDU[2:4])
				attrs["address"] = addr
				attrs["quantity"] = qty
			}
		}
	}

	// Include raw hex for operator visibility (cap to avoid huge payloads).
	raw := pkt.Payload
	if len(raw) > 512 {
		raw = raw[:512]
	}
	attrs["raw_hex"] = hex.EncodeToString(raw)

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "modbus",
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

func (d *Decoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) {
	return nil, nil
}

// exceptionName returns a human-readable name for Modbus exception codes.
func exceptionName(code uint8) string {
	switch code {
	case 1:
		return "illegal_function"
	case 2:
		return "illegal_data_address"
	case 3:
		return "illegal_data_value"
	case 4:
		return "server_device_failure"
	case 5:
		return "acknowledge"
	case 6:
		return "server_device_busy"
	case 8:
		return "memory_parity_error"
	case 10:
		return "gateway_path_unavailable"
	case 11:
		return "gateway_target_failed"
	default:
		return "unknown"
	}
}

// diagSubFunctionName returns the name of a Diagnostics (FC 8) sub-function.
func diagSubFunctionName(sub uint16) string {
	switch sub {
	case 0:
		return "return_query_data"
	case 1:
		return "restart_comm"
	case 4:
		return "force_listen_only"
	case 10:
		return "clear_counters"
	case 20:
		return "clear_overrun"
	default:
		return "unknown"
	}
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
