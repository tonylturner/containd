// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func snmpFlowState(srcPort, dstPort uint16) *flow.State {
	return flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   17,
	}, time.Now())
}

func TestSNMPPorts(t *testing.T) {
	d := NewSNMPDecoder()
	tcp, udp := d.Ports()
	if len(tcp) != 0 {
		t.Fatalf("expected no TCP ports, got %v", tcp)
	}
	want := map[uint16]bool{161: true, 162: true}
	for _, p := range udp {
		if !want[p] {
			t.Fatalf("unexpected UDP port %d", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Fatalf("missing UDP ports: %v", want)
	}
}

func TestSNMPv2cGetRequest(t *testing.T) {
	d := NewSNMPDecoder()
	st := snmpFlowState(32768, 161)
	pkt := &dpi.ParsedPacket{
		Payload: buildSNMPv2cPacket(1, "public", pduGetRequest, 1234, 0, 0, "1.3.6.1.2.1.1.1.0"),
		Proto:   "udp",
		SrcPort: 32768,
		DstPort: 161,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "snmp" {
		t.Errorf("proto=%q, want snmp", ev.Proto)
	}
	if ev.Kind != "get_request" {
		t.Errorf("kind=%q, want get_request", ev.Kind)
	}
	if v := ev.Attributes["version"]; v != "v2c" {
		t.Errorf("version=%v, want v2c", v)
	}
	if v := ev.Attributes["community"]; v != "public" {
		t.Errorf("community=%v, want public", v)
	}
	if v := ev.Attributes["request_id"]; v != int64(1234) {
		t.Errorf("request_id=%v, want 1234", v)
	}
	if v := ev.Attributes["error_status"]; v != "noError" {
		t.Errorf("error_status=%v, want noError", v)
	}
	if v := fmt.Sprint(ev.Attributes["oids"]); v != "[1.3.6.1.2.1.1.1.0]" {
		t.Errorf("oids=%v", v)
	}
	if _, ok := ev.Attributes["community_auth"]; ok {
		t.Error("community_auth must not be emitted")
	}
	if _, ok := ev.Attributes["first_oid"]; ok {
		t.Error("first_oid must be replaced by the complete oids list")
	}
}

func TestSNMPv2cGetResponse(t *testing.T) {
	d := NewSNMPDecoder()
	st := snmpFlowState(161, 32768)
	pkt := &dpi.ParsedPacket{
		Payload: buildSNMPv2cPacket(1, "public", pduGetResponse, 1234, 0, 0, "1.3.6.1.2.1.1.1.0"),
		Proto:   "udp",
		SrcPort: 161,
		DstPort: 32768,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "get_response" {
		t.Errorf("kind=%q, want get_response", ev.Kind)
	}
	if v := ev.Attributes["version"]; v != "v2c" {
		t.Errorf("version=%v, want v2c", v)
	}
	if v := ev.Attributes["community"]; v != "public" {
		t.Errorf("community=%v, want public", v)
	}
	if got := fmt.Sprint(ev.Attributes["oids"]); got != "[1.3.6.1.2.1.1.1.0]" {
		t.Errorf("response oids=%v", got)
	}
}

func TestSNMPv1Trap(t *testing.T) {
	d := NewSNMPDecoder()
	st := snmpFlowState(32768, 162)
	// v1 Trap has a different PDU structure; we just verify it's recognized.
	pkt := &dpi.ParsedPacket{
		Payload: buildSNMPv1TrapPacket("public"),
		Proto:   "udp",
		SrcPort: 32768,
		DstPort: 162,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "trap" {
		t.Errorf("kind=%q, want trap", ev.Kind)
	}
	if v := ev.Attributes["version"]; v != "v1" {
		t.Errorf("version=%v, want v1", v)
	}
	if v := ev.Attributes["pdu_type"]; v != "trap" {
		t.Errorf("pdu_type=%v, want trap", v)
	}
	if v := ev.Attributes["community"]; v != "public" {
		t.Errorf("community=%v, want public", v)
	}
	if got := ev.Attributes["enterprise_oid"]; got != "1.3.6.1.4.1.99" {
		t.Errorf("enterprise_oid=%v", got)
	}
	if got := ev.Attributes["generic_trap"]; got != int64(6) {
		t.Errorf("generic_trap=%v", got)
	}
	if got := ev.Attributes["specific_trap"]; got != int64(1) {
		t.Errorf("specific_trap=%v", got)
	}
	if got := fmt.Sprint(ev.Attributes["oids"]); got != "[1.3.6.1.2.1.1.3.0]" {
		t.Errorf("trap oids=%v", got)
	}
}

func TestSNMPv2TrapOID(t *testing.T) {
	d := NewSNMPDecoder()
	st := snmpFlowState(32768, 162)
	packet := buildSNMPv2TrapPacket("public", "1.3.6.1.6.3.1.1.5.3")
	events, err := d.OnPacket(st, &dpi.ParsedPacket{
		Payload: packet, Proto: "udp", SrcPort: 32768, DstPort: 162,
	})
	if err != nil || len(events) != 1 {
		t.Fatalf("OnPacket = %v, %v; want one event", events, err)
	}
	attrs := events[0].Attributes
	if attrs["community"] != "public" || attrs["trap_oid"] != "1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("trap attributes = %#v", attrs)
	}
	if got := fmt.Sprint(attrs["oids"]); got != "[1.3.6.1.6.3.1.1.4.1.0]" {
		t.Errorf("varbind OIDs=%v", got)
	}
}

func TestSNMPSetRequest(t *testing.T) {
	d := NewSNMPDecoder()
	st := snmpFlowState(32768, 161)
	pkt := &dpi.ParsedPacket{
		Payload: buildSNMPv2cPacket(1, "private", pduSetRequest, 5678, 0, 0, "1.3.6.1.2.1.1.5.0"),
		Proto:   "udp",
		SrcPort: 32768,
		DstPort: 161,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "set_request" {
		t.Errorf("kind=%q, want set_request", ev.Kind)
	}
	if v, ok := ev.Attributes["write_operation"]; !ok || v != true {
		t.Errorf("write_operation=%v, want true", v)
	}
}

func TestSNMPShortPacket(t *testing.T) {
	d := NewSNMPDecoder()
	st := snmpFlowState(32768, 161)
	pkt := &dpi.ParsedPacket{
		Payload: []byte{0x30, 0x03},
		Proto:   "udp",
		SrcPort: 32768,
		DstPort: 161,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for short packet, got %d", len(events))
	}
}

func TestSNMPMalformedBER(t *testing.T) {
	d := NewSNMPDecoder()
	st := snmpFlowState(32768, 161)

	tests := []struct {
		name    string
		payload []byte
	}{
		{"wrong tag", []byte{0x31, 0x05, 0x02, 0x01, 0x01, 0x04, 0x00}},
		{"truncated length", []byte{0x30, 0x84}},
		{"zero payload", []byte{}},
		{"bad version tag", []byte{0x30, 0x03, 0x04, 0x01, 0x01}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := &dpi.ParsedPacket{
				Payload: tc.payload,
				Proto:   "udp",
				SrcPort: 32768,
				DstPort: 161,
			}
			events, err := d.OnPacket(st, pkt)
			if err != nil {
				t.Fatalf("OnPacket error: %v", err)
			}
			if len(events) != 0 {
				t.Fatalf("expected 0 events for malformed BER, got %d", len(events))
			}
		})
	}
}

func TestReadBEROIDLargeSecondArc(t *testing.T) {
	oid, _, ok := readBEROID(berTLV(0x06, []byte{0x88, 0x37, 0x03}), 0)
	if !ok || oid != "2.999.3" {
		t.Fatalf("readBEROID = %q, %t; want 2.999.3", oid, ok)
	}
	if _, _, ok := readBEROID(berTLV(0x06, []byte{0x2B, 0x80}), 0); ok {
		t.Fatal("accepted an unterminated OID subidentifier")
	}
}

func TestSNMPCommunityVisible(t *testing.T) {
	d := NewSNMPDecoder()
	st := snmpFlowState(32768, 161)
	community := "my_secret_community"
	pkt := &dpi.ParsedPacket{
		Payload: buildSNMPv2cPacket(1, community, pduGetRequest, 1, 0, 0, "1.3.6.1.2.1.1.1.0"),
		Proto:   "udp",
		SrcPort: 32768,
		DstPort: 161,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]

	if got := ev.Attributes["community"]; got != community {
		t.Errorf("community=%v, want cleartext community %q", got, community)
	}
	if _, ok := ev.Attributes["community_auth"]; ok {
		t.Error("community_auth must not be emitted")
	}
}

func TestSNMPv3VisibleHeaderAndScopedPDU(t *testing.T) {
	d := NewSNMPDecoder()
	state := snmpFlowState(32768, 161)
	packet := buildSNMPv3Packet(0x01, "monitor", false, "1.3.6.1.2.1.1.1.0")
	events, err := d.OnPacket(state, &dpi.ParsedPacket{
		Payload: packet, Proto: "udp", SrcPort: 32768, DstPort: 161,
	})
	if err != nil || len(events) != 1 {
		t.Fatalf("OnPacket = %v, %v; want one event", events, err)
	}
	attrs := events[0].Attributes
	for key, want := range map[string]any{
		"version": "v3", "msg_security_model": int64(3),
		"msg_flags_auth": true, "msg_flags_priv": false, "user_name": "monitor",
	} {
		if attrs[key] != want {
			t.Errorf("%s=%v, want %v", key, attrs[key], want)
		}
	}
	if got := fmt.Sprint(attrs["oids"]); got != "[1.3.6.1.2.1.1.1.0]" {
		t.Errorf("v3 scoped OIDs=%v", got)
	}
}

func TestSNMPv3EncryptedScopedPDUIsNotParsed(t *testing.T) {
	d := NewSNMPDecoder()
	state := snmpFlowState(32768, 161)
	packet := buildSNMPv3Packet(0x03, "monitor", true, "1.3.6.1.2.1.1.1.0")
	events, err := d.OnPacket(state, &dpi.ParsedPacket{
		Payload: packet, Proto: "udp", SrcPort: 32768, DstPort: 161,
	})
	if err != nil || len(events) != 1 {
		t.Fatalf("OnPacket = %v, %v; want one event", events, err)
	}
	attrs := events[0].Attributes
	if attrs["msg_flags_auth"] != true || attrs["msg_flags_priv"] != true || attrs["user_name"] != "monitor" {
		t.Errorf("v3 header attributes = %#v", attrs)
	}
	if _, ok := attrs["oids"]; ok {
		t.Errorf("encrypted scoped PDU must not expose OIDs: %#v", attrs)
	}
}

func TestSNMPVarbindOIDLimit(t *testing.T) {
	var bindings []byte
	for i := 0; i < maxSNMPOIDs+1; i++ {
		bindings = append(bindings, berSequence(append(berOID("1.3.6.1.2.1.1.1.0"), berNull()...))...)
	}
	packet := buildSNMPMessageWithPDU(1, "public", pduGetRequest, bindings)
	events, err := NewSNMPDecoder().OnPacket(snmpFlowState(32768, 161), &dpi.ParsedPacket{
		Payload: packet, Proto: "udp", SrcPort: 32768, DstPort: 161,
	})
	if err != nil || len(events) != 1 {
		t.Fatalf("OnPacket = %v, %v; want one event", events, err)
	}
	if got := len(events[0].Attributes["oids"].([]string)); got != maxSNMPOIDs {
		t.Errorf("oids count=%d, want bound %d", got, maxSNMPOIDs)
	}
	if events[0].Attributes["oids_truncated"] != true {
		t.Error("oids_truncated not set when additional bindings are present")
	}
}

// --- Test helpers: BER packet builders ---

// berSequence wraps content in a BER SEQUENCE (tag 0x30).
func berSequence(content []byte) []byte {
	return berTLV(0x30, content)
}

// berTLV builds a BER TLV with the given tag and value.
func berTLV(tag byte, value []byte) []byte {
	var out []byte
	out = append(out, tag)
	out = appendBERLength(out, len(value))
	out = append(out, value...)
	return out
}

// berInteger builds a BER INTEGER.
func berInteger(v int64) []byte {
	if v >= 0 && v <= 127 {
		return berTLV(0x02, []byte{byte(v)})
	}
	// Encode as variable-length big-endian.
	var buf [8]byte
	n := 0
	tmp := v
	if tmp < 0 {
		// For negative values, find how many bytes needed.
		for i := 7; i >= 0; i-- {
			buf[i] = byte(tmp & 0xFF)
			tmp >>= 8
			n = 8 - i
		}
		// Trim leading 0xFF bytes that are just sign extension.
		start := 8 - n
		for start < 7 && buf[start] == 0xFF && buf[start+1]&0x80 != 0 {
			start++
		}
		return berTLV(0x02, buf[start:8])
	}
	for i := 7; i >= 0; i-- {
		buf[i] = byte(tmp & 0xFF)
		tmp >>= 8
		if tmp == 0 {
			n = 8 - i
			break
		}
	}
	start := 8 - n
	// If high bit is set, prepend a 0x00 byte.
	if buf[start]&0x80 != 0 {
		result := make([]byte, n+1)
		result[0] = 0x00
		copy(result[1:], buf[start:8])
		return berTLV(0x02, result)
	}
	return berTLV(0x02, buf[start:8])
}

// berOctetString builds a BER OCTET STRING.
func berOctetString(s string) []byte {
	return berTLV(0x04, []byte(s))
}

// berOID builds a BER OBJECT IDENTIFIER from dotted notation.
// Only handles simple cases for testing.
func berOID(dotted string) []byte {
	parts := splitOID(dotted)
	if len(parts) < 2 {
		return berTLV(0x06, []byte{0})
	}
	var encoded []byte
	// First two components encoded as X*40+Y.
	encoded = append(encoded, byte(parts[0]*40+parts[1]))
	for i := 2; i < len(parts); i++ {
		encoded = appendBase128(encoded, parts[i])
	}
	return berTLV(0x06, encoded)
}

func splitOID(s string) []int {
	var parts []int
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			n := 0
			for j := start; j < i; j++ {
				n = n*10 + int(s[j]-'0')
			}
			parts = append(parts, n)
			start = i + 1
		}
	}
	return parts
}

func appendBase128(buf []byte, v int) []byte {
	if v < 128 {
		return append(buf, byte(v))
	}
	// Collect base-128 digits in reverse.
	var tmp [10]byte
	n := 0
	for v > 0 {
		tmp[n] = byte(v & 0x7F)
		v >>= 7
		n++
	}
	for i := n - 1; i >= 0; i-- {
		b := tmp[i]
		if i > 0 {
			b |= 0x80
		}
		buf = append(buf, b)
	}
	return buf
}

func appendBERLength(buf []byte, length int) []byte {
	if length < 128 {
		return append(buf, byte(length))
	}
	if length <= 0xFF {
		return append(buf, 0x81, byte(length))
	}
	return append(buf, 0x82, byte(length>>8), byte(length))
}

// berNull returns a BER NULL value.
func berNull() []byte {
	return []byte{0x05, 0x00}
}

// buildSNMPv2cPacket constructs a minimal SNMP v1/v2c packet.
func buildSNMPv2cPacket(version int64, community string, pduType byte, requestID int64, errStatus, errIndex int64, oid string) []byte {
	// Variable binding: SEQUENCE { OID, NULL }.
	binding := berSequence(append(berOID(oid), berNull()...))
	return buildSNMPMessageWithPDU(version, community, pduType, binding, requestID, errStatus, errIndex)
}

func buildSNMPMessageWithPDU(version int64, community string, pduType byte, bindings []byte, requestIDs ...int64) []byte {
	requestID, errStatus, errIndex := int64(1), int64(0), int64(0)
	if len(requestIDs) > 0 {
		requestID = requestIDs[0]
	}
	if len(requestIDs) > 1 {
		errStatus = requestIDs[1]
	}
	if len(requestIDs) > 2 {
		errIndex = requestIDs[2]
	}
	var pduBody []byte
	pduBody = append(pduBody, berInteger(requestID)...)
	pduBody = append(pduBody, berInteger(errStatus)...)
	pduBody = append(pduBody, berInteger(errIndex)...)
	pduBody = append(pduBody, berSequence(bindings)...)

	pdu := berTLV(pduType, pduBody)

	// Message: version, community, PDU.
	var msgBody []byte
	msgBody = append(msgBody, berInteger(version)...)
	msgBody = append(msgBody, berOctetString(community)...)
	msgBody = append(msgBody, pdu...)
	return berSequence(msgBody)
}

func buildSNMPv2TrapPacket(community, trapOID string) []byte {
	binding := berSequence(append(berOID(snmpTrapOID), berOID(trapOID)...))
	var pduBody []byte
	pduBody = append(pduBody, berInteger(1234)...)
	pduBody = append(pduBody, berInteger(0)...)
	pduBody = append(pduBody, berInteger(0)...)
	pduBody = append(pduBody, berSequence(binding)...)
	pdu := berTLV(pduSNMPv2Trap, pduBody)
	msgBody := append(berInteger(1), berOctetString(community)...)
	msgBody = append(msgBody, pdu...)
	return berSequence(msgBody)
}

func buildSNMPv3Packet(flags byte, username string, encrypted bool, oid string) []byte {
	header := append(berInteger(1), berInteger(65507)...)
	header = append(header, berTLV(0x04, []byte{flags})...)
	header = append(header, berInteger(3)...)

	usm := append(berOctetString("\x80\x00\x00\x01"), berInteger(1)...)
	usm = append(usm, berInteger(30)...)
	usm = append(usm, berOctetString(username)...)
	usm = append(usm, berOctetString("auth")...)
	usm = append(usm, berOctetString("priv")...)
	securityParameters := berOctetString(string(berSequence(usm)))

	var scoped []byte
	if encrypted {
		scoped = berOctetString("ciphertext")
	} else {
		binding := berSequence(append(berOID(oid), berNull()...))
		var pduBody []byte
		pduBody = append(pduBody, berInteger(42)...)
		pduBody = append(pduBody, berInteger(0)...)
		pduBody = append(pduBody, berInteger(0)...)
		pduBody = append(pduBody, berSequence(binding)...)
		pdu := berTLV(pduGetRequest, pduBody)
		scoped = berSequence(append(berOctetString("\x80\x00\x00\x01"), append(berOctetString(""), pdu...)...))
	}
	message := append(berInteger(3), berSequence(header)...)
	message = append(message, securityParameters...)
	message = append(message, scoped...)
	return berSequence(message)
}

// buildSNMPv1TrapPacket constructs a minimal SNMPv1 Trap packet.
func buildSNMPv1TrapPacket(community string) []byte {
	// v1 Trap PDU body: enterprise OID, agent-addr, generic-trap, specific-trap, timestamp.
	var trapBody []byte
	trapBody = append(trapBody, berOID("1.3.6.1.4.1.99")...)
	// Agent address: APPLICATION 0, 4 bytes.
	trapBody = append(trapBody, berTLV(0x40, []byte{10, 0, 0, 1})...)
	trapBody = append(trapBody, berInteger(6)...)              // generic-trap: enterpriseSpecific
	trapBody = append(trapBody, berInteger(1)...)              // specific-trap
	trapBody = append(trapBody, berTLV(0x43, []byte{0x00})...) // TimeTicks
	binding := berSequence(append(berOID("1.3.6.1.2.1.1.3.0"), berNull()...))
	trapBody = append(trapBody, berSequence(binding)...)

	pdu := berTLV(pduTrapV1, trapBody)

	var msgBody []byte
	msgBody = append(msgBody, berInteger(0)...) // version v1
	msgBody = append(msgBody, berOctetString(community)...)
	msgBody = append(msgBody, pdu...)

	return berSequence(msgBody)
}
