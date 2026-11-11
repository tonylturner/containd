// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

const (
	maxCommunityLen    = 512
	maxOIDLen          = 1024
	maxSNMPOIDs        = 32
	maxSNMPSecurityLen = 4096
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

const snmpTrapOID = "1.3.6.1.6.3.1.1.4.1.0"

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
		d.parseV3Message(msg, off, attrs)
		return []dpi.Event{newSNMPEvent(state, "v3_message", attrs)}, nil
	}
	if version != 0 && version != 1 {
		return nil, nil
	}

	communityOff, ok := parseSNMPCommunity(msg, off, attrs)
	if !ok {
		return nil, nil
	}
	pduName, pduTag, pduBody, ok := parseSNMPPDU(msg, communityOff, attrs)
	if !ok {
		return nil, nil
	}
	if pduTag == pduSetRequest {
		attrs["write_operation"] = true
	}
	d.parsePDUFields(pduBody, pduTag, attrs)
	return []dpi.Event{newSNMPEvent(state, pduName, attrs)}, nil
}

func (d *SNMPDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

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

func parseSNMPCommunity(msg []byte, off int, attrs map[string]any) (int, bool) {
	value, next, ok := readBERValue(msg, off, 0x04, maxCommunityLen)
	if !ok {
		return 0, false
	}
	attrs["community"] = string(value)
	return next, true
}

func parseSNMPPDU(msg []byte, off int, attrs map[string]any) (string, byte, []byte, bool) {
	return parseSNMPPDUAt(msg, off, attrs)
}

func parseSNMPPDUAt(buf []byte, off int, attrs map[string]any) (string, byte, []byte, bool) {
	if off >= len(buf) {
		return "", 0, nil, false
	}
	pduTag := buf[off]
	pduName, known := pduTypeNames[pduTag]
	if !known {
		return "", 0, nil, false
	}
	body, _, ok := readBERValue(buf, off, pduTag, len(buf))
	if !ok {
		return "", 0, nil, false
	}
	attrs["pdu_type"] = pduName
	return pduName, pduTag, body, true
}

func newSNMPEvent(state *flow.State, kind string, attrs map[string]any) dpi.Event {
	return dpi.Event{
		FlowID:     state.ID(),
		Proto:      "snmp",
		Kind:       kind,
		Attributes: attrs,
	}
}

func (d *SNMPDecoder) parsePDUFields(body []byte, pduTag byte, attrs map[string]any) {
	if pduTag == pduTrapV1 {
		d.parseV1TrapFields(body, attrs)
		return
	}
	reqID, next, ok := parseSNMPIntegerField(body, 0)
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
	d.parseVarbindList(body, next, pduTag == pduSNMPv2Trap, attrs)
}

func (d *SNMPDecoder) parseV1TrapFields(body []byte, attrs map[string]any) {
	enterprise, next, ok := readBEROID(body, 0)
	if !ok {
		return
	}
	attrs["enterprise_oid"] = enterprise
	agent, next, ok := readBERValue(body, next, 0x40, 4)
	if !ok || len(agent) != 4 {
		return
	}
	generic, next, ok := parseSNMPIntegerField(body, next)
	if !ok {
		return
	}
	specific, next, ok := parseSNMPIntegerField(body, next)
	if !ok {
		return
	}
	attrs["generic_trap"] = generic
	attrs["specific_trap"] = specific
	_, next, ok = readBERValue(body, next, 0x43, 8)
	if !ok {
		return
	}
	d.parseVarbindList(body, next, false, attrs)
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

func (d *SNMPDecoder) parseVarbindList(body []byte, off int, v2Trap bool, attrs map[string]any) {
	list, _, ok := readBERValue(body, off, 0x30, len(body))
	if !ok {
		return
	}
	var oids []string
	pos := 0
	for pos < len(list) && len(oids) < maxSNMPOIDs {
		binding, next, ok := readBERValue(list, pos, 0x30, len(list))
		if !ok {
			break
		}
		oid, valueOff, ok := readBEROID(binding, 0)
		if !ok {
			break
		}
		oids = append(oids, oid)
		if v2Trap && oid == snmpTrapOID && valueOff < len(binding) && binding[valueOff] == 0x06 {
			trapOID, _, valid := readBEROID(binding, valueOff)
			if valid {
				attrs["trap_oid"] = trapOID
			}
		}
		pos = next
	}
	attrs["oids"] = oids
	if pos < len(list) && len(oids) == maxSNMPOIDs {
		attrs["oids_truncated"] = true
	}
}

func (d *SNMPDecoder) parseV3Message(msg []byte, off int, attrs map[string]any) {
	header, next, ok := readBERValue(msg, off, 0x30, len(msg))
	if !ok {
		return
	}
	flags, securityModel, ok := parseSNMPv3Header(header)
	if !ok {
		return
	}
	attrs["msg_flags_auth"] = flags&0x01 != 0
	attrs["msg_flags_priv"] = flags&0x02 != 0
	attrs["msg_security_model"] = securityModel

	securityParameters, next, ok := readBERValue(msg, next, 0x04, maxSNMPSecurityLen)
	if !ok {
		return
	}
	if securityModel == 3 {
		if userName, found := parseUSMUserName(securityParameters); found {
			attrs["user_name"] = userName
		}
	}

	if flags&0x02 != 0 || next >= len(msg) || msg[next] != 0x30 {
		return
	}
	scopedPDU, _, ok := readBERValue(msg, next, 0x30, len(msg))
	if !ok {
		return
	}
	_, pos, ok := readBERValue(scopedPDU, 0, 0x04, len(scopedPDU))
	if !ok {
		return
	}
	_, pos, ok = readBERValue(scopedPDU, pos, 0x04, len(scopedPDU))
	if !ok {
		return
	}
	_, pduTag, body, ok := parseSNMPPDUAt(scopedPDU, pos, attrs)
	if !ok {
		return
	}
	if pduTag == pduSetRequest {
		attrs["write_operation"] = true
	}
	d.parsePDUFields(body, pduTag, attrs)
}

func parseSNMPv3Header(header []byte) (byte, int64, bool) {
	pos := 0
	if _, next, ok := readBERValue(header, pos, 0x02, 8); ok {
		pos = next
	} else {
		return 0, 0, false
	}
	if _, next, ok := readBERValue(header, pos, 0x02, 8); ok {
		pos = next
	} else {
		return 0, 0, false
	}
	flags, next, ok := readBERValue(header, pos, 0x04, 1)
	if !ok || len(flags) != 1 {
		return 0, 0, false
	}
	pos = next
	securityModel, _, ok := parseSNMPIntegerField(header, pos)
	if !ok {
		return 0, 0, false
	}
	return flags[0], securityModel, true
}

func parseUSMUserName(parameters []byte) (string, bool) {
	sequence, _, ok := readBERValue(parameters, 0, 0x30, maxSNMPSecurityLen)
	if !ok {
		return "", false
	}
	pos := 0
	tags := [...]byte{0x04, 0x02, 0x02, 0x04}
	maxLens := [...]int{32, 8, 8, 256}
	for field, tag := range tags {
		value, next, ok := readBERValue(sequence, pos, tag, maxLens[field])
		if !ok {
			return "", false
		}
		if field == 3 {
			return string(value), true
		}
		pos = next
	}
	return "", false
}

func readBERValue(buf []byte, off int, tag byte, maxLen int) ([]byte, int, bool) {
	if off >= len(buf) || buf[off] != tag {
		return nil, off, false
	}
	length, valueOff, ok := readBERLength(buf, off+1)
	if !ok || length > maxLen || valueOff+length > len(buf) {
		return nil, off, false
	}
	return buf[valueOff : valueOff+length], valueOff + length, true
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
	val := int64(int8(buf[vOff]))
	for i := 1; i < vLen; i++ {
		val = (val << 8) | int64(buf[vOff+i])
	}
	return val, vOff + vLen, true
}

// readBEROID reads a BER OBJECT IDENTIFIER (tag 0x06) starting at buf[off]
// and returns the dotted-notation string, offset past the element, and success.
func readBEROID(buf []byte, off int) (string, int, bool) {
	oidBytes, next, ok := readBERValue(buf, off, 0x06, maxOIDLen)
	if !ok || len(oidBytes) == 0 {
		return "", off, false
	}
	var subIDs []uint64
	var value uint64
	for _, b := range oidBytes {
		if value > 0xFFFFFFFF>>7 {
			return "", off, false
		}
		value = value<<7 | uint64(b&0x7F)
		if b&0x80 == 0 {
			subIDs = append(subIDs, value)
			value = 0
		}
	}
	if value != 0 || len(subIDs) == 0 || oidBytes[len(oidBytes)-1]&0x80 != 0 {
		return "", off, false
	}
	first := subIDs[0]
	x, y := uint64(2), first-80
	if first < 40 {
		x, y = 0, first
	} else if first < 80 {
		x, y = 1, first-40
	}
	var b strings.Builder
	b.Grow(64)
	fmt.Fprintf(&b, "%d.%d", x, y)
	for _, subID := range subIDs[1:] {
		fmt.Fprintf(&b, ".%d", subID)
		if b.Len() > maxOIDLen {
			return "", off, false
		}
	}
	return b.String(), next, true
}
