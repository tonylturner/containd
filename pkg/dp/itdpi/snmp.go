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

	p := pkt.Payload

	// Outer SEQUENCE tag.
	if len(p) < 2 || p[0] != 0x30 {
		return nil, nil
	}
	seqLen, seqOff, ok := readBERLength(p, 1)
	if !ok || seqOff+seqLen > len(p) {
		return nil, nil
	}
	msg := p[seqOff : seqOff+seqLen]

	// Version INTEGER.
	if len(msg) < 2 || msg[0] != 0x02 {
		return nil, nil
	}
	version, vOff, ok := readBERInteger(msg, 0)
	if !ok {
		return nil, nil
	}

	var versionStr string
	switch version {
	case 0:
		versionStr = "v1"
	case 1:
		versionStr = "v2c"
	case 3:
		versionStr = "v3"
	default:
		versionStr = fmt.Sprintf("unknown(%d)", version)
	}

	attrs := map[string]any{
		"version":   versionStr,
		"src_port":  pkt.SrcPort,
		"dst_port":  pkt.DstPort,
		"transport": pkt.Proto,
	}

	off := vOff

	if version == 3 {
		// SNMPv3: after version comes msgGlobalData (SEQUENCE).
		// Try to extract msgSecurityModel from it.
		d.parseV3Header(msg, off, attrs)

		// We cannot easily determine PDU type for v3 without decryption,
		// so emit a generic event.
		ev := dpi.Event{
			FlowID:     state.Key.Hash(),
			Proto:      "snmp",
			Kind:       "v3_message",
			Attributes: attrs,
			Timestamp:  time.Now().UTC(),
		}
		return []dpi.Event{ev}, nil
	}

	// v1/v2c: community string (OCTET STRING, tag 0x04).
	if off >= len(msg) || msg[off] != 0x04 {
		return nil, nil
	}
	commLen, commOff, ok := readBERLength(msg, off+1)
	if !ok || commLen > maxCommunityLen || commOff+commLen > len(msg) {
		return nil, nil
	}
	// REDACT: only record the length, never the actual community string.
	attrs["community_length"] = commLen
	attrs["community_auth"] = true
	off = commOff + commLen

	// PDU: context-specific tag 0xA0-0xA8.
	if off >= len(msg) {
		return nil, nil
	}
	pduTag := msg[off]
	pduName, known := pduTypeNames[pduTag]
	if !known {
		return nil, nil
	}
	attrs["pdu_type"] = pduName

	pduLen, pduOff, ok := readBERLength(msg, off+1)
	if !ok || pduOff+pduLen > len(msg) {
		return nil, nil
	}
	pduBody := msg[pduOff : pduOff+pduLen]

	if pduTag == pduSetRequest {
		attrs["write_operation"] = true
	}

	// Parse request-id, error-status, error-index from PDU body.
	// (v1 Trap has a different structure, skip for that.)
	if pduTag != pduTrapV1 {
		d.parsePDUFields(pduBody, attrs)
	}

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "snmp",
		Kind:       pduName,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

func (d *SNMPDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

// parsePDUFields extracts request-id, error-status, error-index, and the
// first OID from the variable bindings in a non-Trap PDU body.
func (d *SNMPDecoder) parsePDUFields(body []byte, attrs map[string]any) {
	off := 0

	// request-id (INTEGER).
	if off >= len(body) || body[off] != 0x02 {
		return
	}
	reqID, next, ok := readBERInteger(body, off)
	if !ok {
		return
	}
	attrs["request_id"] = reqID
	off = next

	// error-status (INTEGER).
	if off >= len(body) || body[off] != 0x02 {
		return
	}
	errStatus, next, ok := readBERInteger(body, off)
	if !ok {
		return
	}
	if name, known := errorStatusNames[errStatus]; known {
		attrs["error_status"] = name
	} else {
		attrs["error_status"] = fmt.Sprintf("%d", errStatus)
	}
	off = next

	// error-index (INTEGER).
	if off >= len(body) || body[off] != 0x02 {
		return
	}
	_, next, ok = readBERInteger(body, off)
	if !ok {
		return
	}
	off = next

	// Variable bindings: SEQUENCE of SEQUENCE { OID, value }.
	if off >= len(body) || body[off] != 0x30 {
		return
	}
	vbLen, vbOff, ok := readBERLength(body, off+1)
	if !ok || vbOff+vbLen > len(body) {
		return
	}
	vb := body[vbOff : vbOff+vbLen]

	// Extract just the first binding.
	if len(vb) < 2 || vb[0] != 0x30 {
		return
	}
	bindLen, bindOff, ok := readBERLength(vb, 1)
	if !ok || bindOff+bindLen > len(vb) {
		return
	}
	binding := vb[bindOff : bindOff+bindLen]

	// First element should be an OID (tag 0x06).
	if len(binding) < 2 || binding[0] != 0x06 {
		return
	}
	oid, _, ok := readBEROID(binding, 0)
	if ok && len(oid) <= maxOIDLen {
		attrs["first_oid"] = oid
	}
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
