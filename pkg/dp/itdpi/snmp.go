// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"fmt"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

const (
	maxCommunityLen = 512
	maxOIDLen       = 1024
)

// SNMP PDU type tags (context-specific, constructed).
const (
	pduGetRequest     = 0xA0
	pduGetNextRequest = 0xA1
	pduGetResponse    = 0xA2
	pduSetRequest     = 0xA3
	pduTrapV1         = 0xA4
	pduGetBulkRequest = 0xA5
	pduInformRequest  = 0xA6
	pduSNMPv2Trap     = 0xA7
	pduReport         = 0xA8
)

var pduTypeNames = map[byte]string{
	pduGetRequest:     "get_request",
	pduGetNextRequest: "get_next_request",
	pduGetResponse:    "get_response",
	pduSetRequest:     "set_request",
	pduTrapV1:         "trap",
	pduGetBulkRequest: "get_bulk_request",
	pduInformRequest:  "inform_request",
	pduSNMPv2Trap:     "snmpv2_trap",
	pduReport:         "report",
}

var errorStatusNames = map[int64]string{
	0: "noError",
	1: "tooBig",
	2: "noSuchName",
	3: "badValue",
	4: "readOnly",
	5: "genErr",
}

// SNMPDecoder parses SNMP v1/v2c/v3 messages and emits protocol events.
type SNMPDecoder struct{}

func NewSNMPDecoder() *SNMPDecoder { return &SNMPDecoder{} }

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *SNMPDecoder) Ports() (tcpPorts, udpPorts []uint16) {
	return nil, []uint16{161, 162}
}

func (d *SNMPDecoder) Supports(state *flow.State) bool {
	if state == nil || state.Key.Proto != 17 {
		return false
	}
	switch state.Key.SrcPort {
	case 161, 162:
		return true
	}
	switch state.Key.DstPort {
	case 161, 162:
		return true
	}
	return false
}

func (d *SNMPDecoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}
	msg, version, off, ok := parseSNMPMessage(pkt.Payload)
	if !ok {
		return nil, nil
	}
	attrs := snmpBaseAttrs(pkt, version)
	if version == 3 {
		d.parseV3Header(msg, off, attrs)
		return []dpi.Event{newSNMPEvent(state, "v3_message", attrs)}, nil
	}

	pduName, pduTag, pduBody, ok := parseSNMPPDU(msg, off, attrs)
	if !ok {
		return nil, nil
	}
	if pduTag == pduSetRequest {
		attrs["write_operation"] = true
	}
	if pduTag != pduTrapV1 {
		d.parsePDUFields(pduBody, attrs)
	}
	return []dpi.Event{newSNMPEvent(state, pduName, attrs)}, nil
}

func (d *SNMPDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

// parsePDUFields extracts request-id, error-status, error-index, and the
// first OID from the variable bindings in a non-Trap PDU body.
func (d *SNMPDecoder) parsePDUFields(body []byte, attrs map[string]any) {
	off := 0
	reqID, next, ok := parseSNMPIntegerField(body, off)
	if !ok {
		return
	}
	attrs["request_id"] = reqID
	errStatus, next, ok := parseSNMPIntegerField(body, next)
	if !ok {
		return
	}
	attrs["error_status"] = snmpErrorStatus(errStatus)
	_, next, ok = parseSNMPIntegerField(body, next)
	if !ok {
		return
	}
	binding, ok := firstSNMPBinding(body, next)
	if !ok {
		return
	}
	oid, _, ok := readBEROID(binding, 0)
	if ok && len(oid) <= maxOIDLen {
		attrs["first_oid"] = oid
	}
}

func parseSNMPMessage(p []byte) ([]byte, int64, int, bool) {
	if len(p) < 2 || p[0] != 0x30 {
		return nil, 0, 0, false
	}
	seqLen, seqOff, ok := readBERLength(p, 1)
	if !ok || seqOff+seqLen > len(p) {
		return nil, 0, 0, false
	}
	msg := p[seqOff : seqOff+seqLen]
	if len(msg) < 2 || msg[0] != 0x02 {
		return nil, 0, 0, false
	}
	version, off, ok := readBERInteger(msg, 0)
	if !ok {
		return nil, 0, 0, false
	}
	return msg, version, off, true
}

func snmpBaseAttrs(pkt *dpi.ParsedPacket, version int64) map[string]any {
	return map[string]any{
		"version":   snmpVersionString(version),
		"src_port":  pkt.SrcPort,
		"dst_port":  pkt.DstPort,
		"transport": pkt.Proto,
	}
}

func snmpVersionString(version int64) string {
	switch version {
	case 0:
		return "v1"
	case 1:
		return "v2c"
	case 3:
		return "v3"
	default:
		return fmt.Sprintf("unknown(%d)", version)
	}
}

func parseSNMPPDU(msg []byte, off int, attrs map[string]any) (string, byte, []byte, bool) {
	next, ok := parseSNMPCommunity(msg, off, attrs)
	if !ok || next >= len(msg) {
		return "", 0, nil, false
	}
	pduTag := msg[next]
	pduName, known := pduTypeNames[pduTag]
	if !known {
		return "", 0, nil, false
	}
	attrs["pdu_type"] = pduName
	pduLen, pduOff, ok := readBERLength(msg, next+1)
	if !ok || pduOff+pduLen > len(msg) {
		return "", 0, nil, false
	}
	return pduName, pduTag, msg[pduOff : pduOff+pduLen], true
}

func parseSNMPCommunity(msg []byte, off int, attrs map[string]any) (int, bool) {
	if off >= len(msg) || msg[off] != 0x04 {
		return 0, false
	}
	commLen, commOff, ok := readBERLength(msg, off+1)
	if !ok || commLen > maxCommunityLen || commOff+commLen > len(msg) {
		return 0, false
	}
	attrs["community_length"] = commLen
	attrs["community_auth"] = true
	return commOff + commLen, true
}

func newSNMPEvent(state *flow.State, kind string, attrs map[string]any) dpi.Event {
	return dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "snmp",
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
}

func parseSNMPIntegerField(body []byte, off int) (int64, int, bool) {
	if off >= len(body) || body[off] != 0x02 {
		return 0, 0, false
	}
	return readBERInteger(body, off)
}

func snmpErrorStatus(code int64) string {
	if name, known := errorStatusNames[code]; known {
		return name
	}
	return fmt.Sprintf("%d", code)
}

func firstSNMPBinding(body []byte, off int) ([]byte, bool) {
	if off >= len(body) || body[off] != 0x30 {
		return nil, false
	}
	vbLen, vbOff, ok := readBERLength(body, off+1)
	if !ok || vbOff+vbLen > len(body) {
		return nil, false
	}
	vb := body[vbOff : vbOff+vbLen]
	if len(vb) < 2 || vb[0] != 0x30 {
		return nil, false
	}
	bindLen, bindOff, ok := readBERLength(vb, 1)
	if !ok || bindOff+bindLen > len(vb) {
		return nil, false
	}
	binding := vb[bindOff : bindOff+bindLen]
	if len(binding) < 2 || binding[0] != 0x06 {
		return nil, false
	}
	return binding, true
}

// parseV3Header extracts msgSecurityModel from the SNMPv3 msgGlobalData.
func (d *SNMPDecoder) parseV3Header(msg []byte, off int, attrs map[string]any) {
	if off >= len(msg) || msg[off] != 0x30 {
		return
	}
	hdrLen, hdrOff, ok := readBERLength(msg, off+1)
	if !ok || hdrOff+hdrLen > len(msg) {
		return
	}
	hdr := msg[hdrOff : hdrOff+hdrLen]

	// msgGlobalData SEQUENCE contains:
	//   msgID (INTEGER), msgMaxSize (INTEGER), msgFlags (OCTET STRING),
	//   msgSecurityModel (INTEGER)
	pos := 0
	for i := 0; i < 4; i++ {
		if pos >= len(hdr) {
			return
		}
		tag := hdr[pos]
		if tag == 0x02 && i == 3 {
			// msgSecurityModel
			val, _, ok := readBERInteger(hdr, pos)
			if ok {
				attrs["msg_security_model"] = val
			}
			return
		}
		// Skip this TLV.
		vLen, vOff, ok := readBERLength(hdr, pos+1)
		if !ok || vOff+vLen > len(hdr) {
			return
		}
		pos = vOff + vLen
	}
}

// --- BER/ASN.1 parsing helpers ---

// readBERLength reads a BER length starting at buf[off] and returns the
// length value, the offset past the length field, and success.
func readBERLength(buf []byte, off int) (int, int, bool) {
	if off >= len(buf) {
		return 0, off, false
	}
	b := buf[off]
	if b&0x80 == 0 {
		// Short form: single byte length.
		return int(b), off + 1, true
	}
	numBytes := int(b & 0x7F)
	if numBytes == 0 || numBytes > 4 || off+1+numBytes > len(buf) {
		return 0, off, false
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(buf[off+1+i])
	}
	if length < 0 {
		return 0, off, false
	}
	return length, off + 1 + numBytes, true
}

// readBERInteger reads a BER INTEGER (tag 0x02) starting at buf[off]
// and returns the value, offset past the element, and success.
func readBERInteger(buf []byte, off int) (int64, int, bool) {
	if off >= len(buf) || buf[off] != 0x02 {
		return 0, off, false
	}
	vLen, vOff, ok := readBERLength(buf, off+1)
	if !ok || vLen == 0 || vLen > 8 || vOff+vLen > len(buf) {
		return 0, off, false
	}
	// Sign-extend the first byte.
	val := int64(int8(buf[vOff]))
	for i := 1; i < vLen; i++ {
		val = (val << 8) | int64(buf[vOff+i])
	}
	return val, vOff + vLen, true
}

// readBEROID reads a BER OBJECT IDENTIFIER (tag 0x06) starting at buf[off]
// and returns the dotted-notation string, offset past the element, and success.
func readBEROID(buf []byte, off int) (string, int, bool) {
	if off >= len(buf) || buf[off] != 0x06 {
		return "", off, false
	}
	vLen, vOff, ok := readBERLength(buf, off+1)
	if !ok || vLen == 0 || vOff+vLen > len(buf) {
		return "", off, false
	}
	oidBytes := buf[vOff : vOff+vLen]

	var b strings.Builder
	b.Grow(64)

	// First byte encodes first two components: X*40 + Y.
	first := int(oidBytes[0])
	x := first / 40
	y := first % 40
	fmt.Fprintf(&b, "%d.%d", x, y)

	// Remaining bytes: base-128 encoded sub-identifiers.
	val := uint64(0)
	for i := 1; i < len(oidBytes); i++ {
		val = (val << 7) | uint64(oidBytes[i]&0x7F)
		if val > 0xFFFFFFFF {
			// Unreasonably large sub-identifier.
			return "", off, false
		}
		if oidBytes[i]&0x80 == 0 {
			fmt.Fprintf(&b, ".%d", val)
			val = 0
		}
	}

	result := b.String()
	if len(result) > maxOIDLen {
		return "", off, false
	}

	return result, vOff + vLen, true
}
