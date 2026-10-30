// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package modbus

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Decoder implements dpi.StreamDecoder for Modbus/TCP visibility.
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
	key := state.ServiceKey()
	return key.SrcPort == ics.ModbusPort || key.DstPort == ics.ModbusPort
}

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *Decoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{ics.ModbusPort}, nil
}

// Protocol implements dpi.StreamDecoder.
func (d *Decoder) Protocol() string { return eventfields.ProtoModbus }

// ParseStream frames the Modbus/TCP stream into ADUs (MBAP header plus PDU)
// and emits one event per complete ADU. An incomplete tail is NeedMore. Bytes
// that cannot start an ADU (an MBAP length outside 2..254) end the parse with
// a *dpi.FrameError carrying its malformed event.
func (d *Decoder) ParseStream(state *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	var res dpi.StreamResult
	pos := 0
	for pos < len(v.Bytes) {
		n, err := frameADU(v.Bytes[pos:])
		if err != nil {
			res.Consumed = pos
			return res, &dpi.FrameError{
				Offset: v.Base + int64(pos),
				Reason: err.Error(),
				Event:  malformedEvent(state, v.Bytes[pos:], err),
			}
		}
		if n == 0 {
			res.NeedMore = true
			break
		}
		adu := v.Bytes[pos : pos+n]
		res.Frames = append(res.Frames, dpi.DecodedFrame{
			Start:  v.Base + int64(pos),
			End:    v.Base + int64(pos+n),
			Events: []dpi.Event{aduEvent(state, decodeADU(adu), adu)},
		})
		pos += n
	}
	res.Consumed = pos
	return res, nil
}

// OnPacket parses pkt.Payload as a stream that starts at an ADU boundary,
// with the same framing as ParseStream. It returns every complete ADU's event
// and, when framing fails, the malformed event and the *dpi.FrameError.
func (d *Decoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}
	res, err := d.ParseStream(state, dpi.StreamView{Session: flowID(state), Base: pkt.Offset, Bytes: pkt.Payload})
	var events []dpi.Event
	for _, f := range res.Frames {
		events = append(events, f.Events...)
	}
	var fe *dpi.FrameError
	if errors.As(err, &fe) {
		return append(events, fe.Event), fe
	}
	return events, nil
}

func aduEvent(state *flow.State, frame *TCPFrame, adu []byte) dpi.Event {
	fc := frame.FunctionCode
	isException := fc >= 128

	attrs := map[string]any{
		"transaction_id":            frame.TransactionID,
		eventfields.KeyUnitID:       frame.UnitID,
		eventfields.KeyFunctionCode: fc,
	}
	kind := "request"
	if state != nil && state.ServiceKey().Dir == flow.DirReverse {
		kind = "response"
	}

	if isException {
		kind = "exception"
		baseFc := fc - 128
		attrs[eventfields.KeyFunctionCode] = baseFc
		addAccess(attrs, classifyAccess(baseFc, nil))
		if len(frame.PDU) >= 1 {
			ec := frame.PDU[0]
			attrs["exception_code"] = ec
			attrs["exception_description"] = exceptionName(ec)
		}
	} else {
		addAccess(attrs, classifyAccess(fc, frame.PDU))

		switch fc {
		case 8: // Diagnostics — sub-function is first 2 bytes of PDU.
			if len(frame.PDU) >= 2 {
				sub := binary.BigEndian.Uint16(frame.PDU[0:2])
				attrs["sub_function"] = sub
				if desc, ok := diagnosticSubfunctions[sub]; ok {
					attrs["sub_function_name"] = desc.name
				} else {
					attrs["sub_function_name"] = "unknown"
					// Framed diagnostics outside the supported serial-line profile.
					attrs[eventfields.KeyUndecoded] = []string{"modbus.diagnostics_subfunction"}
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
			if kind == "response" {
				addResponseFields(fc, frame.PDU, attrs)
			} else {
				addRequestFields(fc, frame.PDU, attrs)
			}
		}
	}

	addConformance(state, frame, kind, attrs)
	attrs["raw_hex"] = rawHex(adu)

	return dpi.Event{
		FlowID:     flowID(state),
		Proto:      eventfields.ProtoModbus,
		Kind:       kind,
		Attributes: attrs,
	}
}

func addAccess(attrs map[string]any, category accessCategory) {
	if category != accessUnknown {
		attrs[eventfields.KeyIsWrite] = category == accessWrite
	}
}

// malformedEvent describes bytes at an offset that cannot start an ADU.
// Nothing in an unframeable header is trustworthy, so it carries only the
// error and the bytes.
func malformedEvent(state *flow.State, b []byte, err error) dpi.Event {
	return dpi.Event{
		FlowID: flowID(state),
		Proto:  eventfields.ProtoModbus,
		Kind:   eventfields.KindMalformed,
		Attributes: map[string]any{
			eventfields.KeyError: err.Error(),
			"raw_hex":            rawHex(b),
		},
	}
}

// rawHex encodes at most maxRawHex bytes for operator visibility.
func rawHex(b []byte) string {
	if len(b) > maxRawHex {
		b = b[:maxRawHex]
	}
	return hex.EncodeToString(b)
}

const maxRawHex = 512

func flowID(state *flow.State) string {
	if state == nil {
		return ""
	}
	return state.ID()
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
