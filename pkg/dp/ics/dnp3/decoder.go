// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Decoder implements dpi.Decoder for DNP3 visibility.
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
	return state.Key.SrcPort == 20000 || state.Key.DstPort == 20000
}

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *Decoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{20000}, nil
}

// OnPacket decodes every complete DNP3 link-layer frame in the payload.
func (d *Decoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil {
		return nil, nil
	}
	events, _ := d.DecodeStream(state, pkt.Payload)
	return events, nil
}

// DecodeStream implements dpi.StreamDecoder: it emits one event per
// complete link-layer frame at the start of stream and reports the bytes
// they occupy. A trailing partial frame is left for the next segment. Bad
// start bytes or a bad header CRC discard the rest of the stream.
func (d *Decoder) DecodeStream(state *flow.State, stream []byte) ([]dpi.Event, int) {
	var events []dpi.Event
	off := 0
	for off < len(stream) {
		rest := stream[off:]
		if len(rest) < 2 {
			break
		}
		if rest[0] != startByte1 || rest[1] != startByte2 {
			return events, len(stream)
		}
		if len(rest) < headerLen {
			break
		}
		frameLen := wireFrameLen(rest[2])
		if len(rest) < frameLen {
			if _, err := ParseFrame(rest[:headerLen]); err != nil {
				return events, len(stream)
			}
			break
		}
		frame, err := ParseFrame(rest[:frameLen])
		if err != nil {
			return events, len(stream)
		}
		events = append(events, frameEvent(state, frame, rest[:frameLen]))
		off += frameLen
	}
	return events, off
}

// frameEvent builds the DPI event for one parsed frame; raw is its wire
// bytes.
func frameEvent(state *flow.State, frame *DNP3Frame, raw []byte) dpi.Event {
	fc := frame.FunctionCode
	isWrite := IsWriteFunctionCode(fc)
	isControl := IsControlFunctionCode(fc)

	kind := "request"
	if IsResponse(fc) {
		kind = "response"
	}
	// Classify dangerous function codes.
	if IsRestartFunctionCode(fc) {
		kind = "restart"
	} else if fc == FuncStopApplication || fc == FuncSaveConfiguration {
		kind = "control"
	}

	attrs := map[string]any{
		"function_code":       fc,
		"function_name":       FunctionCodeName(fc),
		"is_write":            isWrite,
		"is_control":          isControl,
		"source_address":      frame.Source,
		"destination_address": frame.Destination,
	}

	// Extract IIN flags from response messages.
	if iin1, iin2, ok := frame.IIN(); ok {
		flags := FormatIINFlags(iin1, iin2)
		if flags != "" {
			attrs["iin_flags"] = flags
		}
	}

	// Parse all object group headers.
	objOffset := 3 // Transport + AppControl + FuncCode
	if IsResponse(fc) {
		objOffset = 5 // +2 IIN bytes
	}
	objHeaders := ParseObjectHeaders(frame.Data, objOffset)
	if len(objHeaders) > 0 {
		// Emit comma-separated object groups.
		var b strings.Builder
		for i, oh := range objHeaders {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.FormatUint(uint64(oh.Group), 10))
		}
		attrs["object_groups"] = b.String()

		// Emit first header's qualifier and count for primary inspection.
		attrs["qualifier"] = objHeaders[0].Qualifier
		attrs["object_count"] = objHeaders[0].Count
	}

	// Include raw hex for operator visibility (cap to avoid huge payloads).
	if len(raw) > 512 {
		raw = raw[:512]
	}
	attrs["raw_hex"] = hex.EncodeToString(raw)

	return dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "dnp3",
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
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
