// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package iec104 decodes IEC 60870-5-104 APDUs from a TCP byte stream into
// containd ICS events (milestone B spec §5.5 and §7; contracts K2, K4).
//
// Standards: IEC 60870-5-104 Edition 2.0 (2006) and IEC 60870-5-101
// Edition 2.0 (2003). Clause references:
//   - 104 clause 5: APCI. Start octet 0x68, length octet 4..253, I-, S- and
//     U-format control fields with their reserved bits; N(S) and N(R) are
//     15-bit little-endian, shifted left by one (apci.go).
//   - 104 clause 9: the IEC 104 parameters fix COT at 2 octets, CA at 2 and
//     IOA at 3; reverse-direction operation is permitted.
//   - 101 7.2.1-7.2.5: data unit identifier. Type ID, VSQ (SQ bit 7, number
//     bits 0-6), COT (cause bits 0-5, P/N bit 6, T bit 7, originator
//     address), CA (65535 is the global address), IOA (asdu.go).
//   - 101 7.2.6: information elements, including SIQ, DIQ, QDS, SCO, DCO,
//     RCO, QOS, BSI, COI, QOI, QCC, QRP and CP56Time2a (7.2.6.18).
//   - 101 7.3: the ASDUs of the descriptor table in types.go.
//
// The sub-clause numbers were taken from the editions' structure without
// the licensed text at hand; verify them, and every rule, against the
// licensed editions and the lib60870 captures before release (spec §7.2).
//
// B profile restrictions (the standard allows them; B rejects them as
// malformed with an error that starts with "profile:"): control and system
// types with SQ=1 or more than one object; monitor-direction types (1..44)
// from the client; control or system types from the server with cause 6 or 8.
// The descriptor table marks monitor types that accept SQ=1; this includes
// time-tagged types because each sequenced object retains its own timestamp.
//
// The decoder never resynchronises: bytes that cannot start an APDU end the
// parse with a *dpi.FrameError, and nothing after them is parsed.
package iec104

import (
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Port is the IEC 104 TCP port (IEC 60870-5-104 clause 5).
const Port = 2404

// maxRawHex bounds raw_hex to one maximal APDU (spec §5.5).
const maxRawHex = 2 + maxAPDULength

// Decoder implements dpi.StreamDecoder for IEC 60870-5-104.
type Decoder struct{}

// NewDecoder returns an IEC 104 decoder. It is stateless.
func NewDecoder() *Decoder { return &Decoder{} }

// Supports reports TCP flows with either endpoint on port 2404.
func (d *Decoder) Supports(state *flow.State) bool {
	if state == nil || state.Key.Proto != 6 {
		return false
	}
	return state.Key.SrcPort == Port || state.Key.DstPort == Port
}

// Ports implements dpi.PortHinter.
func (d *Decoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{Port}, nil
}

// Protocol implements dpi.StreamDecoder.
func (d *Decoder) Protocol() string { return eventfields.ProtoIEC104 }

// OnFlowEnd emits nothing: the decoder keeps no per-flow state.
func (d *Decoder) OnFlowEnd(*flow.State) ([]dpi.Event, error) { return nil, nil }

// ParseStream decodes every complete APDU in v. Each APDU is one
// dpi.DecodedFrame whose events are one per information object (I-format)
// or one for the APDU (S- and U-format, malformed or unsupported). An APDU
// whose framing is intact but whose content is bad is a malformed or
// unsupported event, and parsing continues. Bytes that cannot be framed end
// the parse with a *dpi.FrameError. Direction comes only from v.Dir and IDs
// only from v.Session: without both the stream cannot be attributed, so the
// parse fails closed.
func (d *Decoder) ParseStream(state *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	var res dpi.StreamResult
	dc, err := newDirContext(state, v)
	if err != nil {
		return res, &dpi.FrameError{Offset: v.Base, Reason: err.Error(), Event: unattributedEvent(state, v.Bytes, err)}
	}
	pos := 0
	for pos < len(v.Bytes) {
		start := v.Base + int64(pos)
		n, err := frameAPDU(v.Bytes[pos:])
		if err != nil {
			res.Consumed = pos
			return res, &dpi.FrameError{Offset: start, Reason: err.Error(), Event: dc.unframeableEvent(start, v.Bytes[pos:], err)}
		}
		if n == 0 {
			res.NeedMore = true
			break
		}
		res.Frames = append(res.Frames, dpi.DecodedFrame{
			Start:  start,
			End:    start + int64(n),
			Events: dc.apduEvents(start, v.Bytes[pos:pos+n]),
		})
		pos += n
	}
	res.Consumed = pos
	return res, nil
}

// OnPacket parses pkt.Payload with ParseStream. Only a packet with the
// session identity of a tracked stream (HasOffset, Session, Dir) can be
// attributed; any other packet fails closed with a FrameError.
func (d *Decoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}
	v := dpi.StreamView{Bytes: pkt.Payload}
	if pkt.HasOffset {
		v.Session, v.Dir, v.Base = pkt.Session, pkt.Dir, pkt.Offset
	}
	res, err := d.ParseStream(state, v)
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

// dirContext is what every event of one stream direction shares.
type dirContext struct {
	flowID    string
	session   string
	dirByte   byte   // eventfields.DirClient or DirServer
	direction string // DirectionRequest or DirectionResponse
}

func newDirContext(state *flow.State, v dpi.StreamView) (dirContext, error) {
	dc := dirContext{flowID: flowID(state), session: v.Session}
	switch v.Dir {
	case dpi.ClientToServer:
		dc.dirByte, dc.direction = eventfields.DirClient, DirectionRequest
	case dpi.ServerToClient:
		dc.dirByte, dc.direction = eventfields.DirServer, DirectionResponse
	default:
		return dc, errors.New("direction unknown")
	}
	if v.Session == "" {
		return dc, errors.New("session unknown")
	}
	return dc, nil
}

// apduEvents decodes one complete APDU that frameAPDU accepted.
func (dc dirContext) apduEvents(start int64, apdu []byte) []dpi.Event {
	a := decodeAPCI(apdu)
	base := dc.baseAttrs(start, apdu)
	base[eventfields.KeyAPCIType] = a.format
	switch a.format {
	case "S", "U":
		base[eventfields.KeyClass] = ClassSystem
		base[eventfields.KeyIsWrite] = false
		if a.format == "S" {
			base[eventfields.KeyReceiveSequence] = a.recvSeq
		} else {
			base[eventfields.KeyUFunction] = a.uFunction
		}
		if a.length != minAPDULength {
			return dc.single(eventfields.KindMalformed, base, fmt.Errorf("%s-format APDU length %d, want 4", a.format, a.length))
		}
		return dc.single(eventfields.KindAPCI, base, nil)
	}
	base[eventfields.KeySendSequence] = a.sendSeq
	base[eventfields.KeyReceiveSequence] = a.recvSeq
	return dc.iFrameEvents(base, apdu[apciLen:])
}

// iFrameEvents decodes the ASDU of an I-format APDU.
func (dc dirContext) iFrameEvents(base map[string]any, asdu []byte) []dpi.Event {
	if len(asdu) < asduHeaderLen {
		return dc.single(eventfields.KindMalformed, base, fmt.Errorf("ASDU of %d octets is shorter than its 6-octet header", len(asdu)))
	}
	h := decodeASDUHeader(asdu)
	h.attrs(base)
	roleErr := checkRole(h, dc.direction)
	d, ok := descriptors[h.typeID]
	if !ok {
		if roleErr != nil {
			return dc.single(eventfields.KindMalformed, base, roleErr)
		}
		return dc.single(eventfields.KindUnsupported, base, fmt.Errorf("type %d has no B descriptor", h.typeID))
	}
	base[eventfields.KeyIsWrite] = isWrite(dc.direction, h.typeID)
	if h.count == 0 {
		return dc.single(eventfields.KindMalformed, base, errors.New("ASDU with zero information objects"))
	}
	if err := checkProfile(h, d); err != nil {
		return dc.single(eventfields.KindMalformed, base, err)
	}
	objects, err := decodeObjects(h, d, asdu[asduHeaderLen:])
	if err != nil {
		return dc.single(eventfields.KindMalformed, base, err)
	}
	if roleErr != nil {
		// The layout decoded: keep the first object as evidence.
		maps.Copy(base, objects[0])
		return dc.single(eventfields.KindMalformed, base, roleErr)
	}
	kind := eventfields.KindResponse
	if dc.direction == DirectionRequest {
		kind = eventfields.KindRequest
	}
	events := make([]dpi.Event, 0, len(objects))
	for _, obj := range objects {
		attrs := make(map[string]any, len(base)+len(obj))
		maps.Copy(attrs, base)
		maps.Copy(attrs, obj)
		events = append(events, dc.event(kind, attrs))
	}
	return events
}

// baseAttrs are the identity attributes of every event of one APDU.
func (dc dirContext) baseAttrs(start int64, raw []byte) map[string]any {
	return map[string]any{
		eventfields.KeyDirection: dc.direction,
		eventfields.KeySessionID: dc.session,
		eventfields.KeyAPDUID:    eventfields.APDUID(dc.session, dc.dirByte, start),
		eventfields.KeyRawHex:    rawHex(raw),
	}
}

// single returns the one event of an S/U-format or error APDU.
func (dc dirContext) single(kind string, attrs map[string]any, err error) []dpi.Event {
	if err != nil {
		attrs[eventfields.KeyError] = err.Error()
	}
	return []dpi.Event{dc.event(kind, attrs)}
}

// unframeableEvent is the FrameError event for bytes that cannot start an
// APDU at start: identity, the bytes and the error.
func (dc dirContext) unframeableEvent(start int64, b []byte, err error) dpi.Event {
	attrs := dc.baseAttrs(start, b)
	attrs[eventfields.KeyError] = err.Error()
	return dc.event(eventfields.KindMalformed, attrs)
}

func (dc dirContext) event(kind string, attrs map[string]any) dpi.Event {
	return dpi.Event{
		FlowID:     dc.flowID,
		Proto:      eventfields.ProtoIEC104,
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
}

// unattributedEvent is the FrameError event of a view without direction or
// session: it carries no IDs and no direction, only the error and bytes.
func unattributedEvent(state *flow.State, b []byte, err error) dpi.Event {
	return dpi.Event{
		FlowID: flowID(state),
		Proto:  eventfields.ProtoIEC104,
		Kind:   eventfields.KindMalformed,
		Attributes: map[string]any{
			eventfields.KeyError:  err.Error(),
			eventfields.KeyRawHex: rawHex(b),
		},
		Timestamp: time.Now().UTC(),
	}
}

func rawHex(b []byte) string {
	if len(b) > maxRawHex {
		b = b[:maxRawHex]
	}
	return hex.EncodeToString(b)
}

func flowID(state *flow.State) string {
	if state == nil {
		return ""
	}
	return state.Key.Hash()
}
