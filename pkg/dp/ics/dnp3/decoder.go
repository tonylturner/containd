// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"encoding/hex"
	"errors"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Decoder implements dpi.StreamDecoder for DNP3 visibility.
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
	return state.Key.SrcPort == ics.DNP3Port || state.Key.DstPort == ics.DNP3Port
}

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *Decoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{ics.DNP3Port}, nil
}

// Protocol implements dpi.StreamDecoder.
func (d *Decoder) Protocol() string { return eventfields.ProtoDNP3 }

// ParseStream frames the DNP3-over-TCP stream into data link frames. Each
// complete frame is one dpi.DecodedFrame. A frame whose user data starts an
// application fragment (transport FIR) yields one event describing that
// fragment's application header and the objects in this frame; continuation
// segments and link-only frames yield none. Application fragments that span
// several link frames are not reassembled. An incomplete tail is NeedMore;
// bytes that cannot start a frame (start octets, header CRC, length) end the
// parse with a *dpi.FrameError carrying its malformed event.
func (d *Decoder) ParseStream(state *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	var res dpi.StreamResult
	pos := 0
	for pos < len(v.Bytes) {
		n, err := frameLinkFrame(v.Bytes[pos:])
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
		raw := v.Bytes[pos : pos+n]
		res.Frames = append(res.Frames, dpi.DecodedFrame{
			Start:  v.Base + int64(pos),
			End:    v.Base + int64(pos+n),
			Events: frameEvents(state, decodeLinkFrame(raw), raw),
		})
		pos += n
	}
	res.Consumed = pos
	return res, nil
}

// OnPacket parses pkt.Payload as a stream that starts at a frame boundary,
// with the same framing as ParseStream. It returns every complete frame's
// events and, when framing fails, the malformed event and the
// *dpi.FrameError.
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

func frameEvents(state *flow.State, frame *DNP3Frame, raw []byte) []dpi.Event {
	if !frame.HasApplicationHeader() {
		return nil
	}
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
		eventfields.KeyFunctionCode: fc,
		"function_name":             FunctionCodeName(fc),
		eventfields.KeyIsWrite:      isWrite,
		"is_control":                isControl,
		"source_address":            frame.Source,
		"destination_address":       frame.Destination,
		eventfields.KeyDirection:    linkDirection(frame.Control),
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
	objHeaders := ParseObjectHeaders(frame.Data, objOffset, fc)
	if len(objHeaders) > 0 {
		// Emit comma-separated object groups.
		var b strings.Builder
		for i, oh := range objHeaders {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.FormatUint(uint64(oh.Group), 10))
		}
		attrs[eventfields.KeyObjectGroups] = b.String()

		// Emit first header's qualifier and count for primary inspection.
		attrs["qualifier"] = objHeaders[0].Qualifier
		if count := objHeaders[0].Count; count <= math.MaxUint16 {
			attrs["object_count"] = uint16(count)
		}
	}

	attrs["raw_hex"] = rawHex(raw)

	return []dpi.Event{{
		FlowID:     flowID(state),
		Proto:      eventfields.ProtoDNP3,
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}}
}

// linkDirection names the station that sent the frame from the link control
// DIR bit: set by the master, clear from an outstation.
func linkDirection(control uint8) string {
	if control&ControlDIR != 0 {
		return "master"
	}
	return "outstation"
}

// malformedEvent describes bytes at an offset that cannot start a frame.
// Nothing in an unframeable header is trustworthy, so it carries only the
// error and the bytes.
func malformedEvent(state *flow.State, b []byte, err error) dpi.Event {
	return dpi.Event{
		FlowID: flowID(state),
		Proto:  eventfields.ProtoDNP3,
		Kind:   eventfields.KindMalformed,
		Attributes: map[string]any{
			eventfields.KeyError: err.Error(),
			"raw_hex":            rawHex(b),
		},
		Timestamp: time.Now().UTC(),
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
	return state.Key.Hash()
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
