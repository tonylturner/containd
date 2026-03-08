// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec61850

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// --- MMS Tests ---

func TestMMSSupportsPort102(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())
	if !dec.Supports(state) {
		t.Fatal("should support TCP port 102 (dst)")
	}
	state2 := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 102, 12345), time.Now())
	if !dec.Supports(state2) {
		t.Fatal("should support TCP port 102 (src)")
	}
}

func TestMMSDoesNotSupportOtherPorts(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 80), time.Now())
	if dec.Supports(state) {
		t.Fatal("should not support TCP port 80")
	}
}

func TestMMSSupportsNil(t *testing.T) {
	dec := NewMMSDecoder()
	if dec.Supports(nil) {
		t.Fatal("should not support nil state")
	}
}

func TestMMSReturnsNilForS7comm(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	// Build a TPKT + COTP DT + S7comm payload (protocol ID 0x32).
	pkt := buildTPKTCOTP([]byte{
		0x32, 0x01, 0x00, 0x00, // S7comm header
		0x00, 0x00, 0x00, 0x0E,
	})

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for S7comm traffic, got %d", len(events))
	}
}

func TestMMSDetectsConfirmedRequest(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	// Build MMS confirmed-request with Read service (tag 0xA4).
	// Outer: confirmed-request (0xA0), inner: invoke-id (int), then read (0xA4).
	mmsPayload := []byte{
		0xA0, 0x0A, // confirmed-request, length 10
		0x02, 0x01, 0x01, // invoke-id = 1 (INTEGER)
		0xA4, 0x05, // Read service, length 5
		0x30, 0x03, 0x0A, 0x01, 0x00, // dummy read content
	}

	pkt := buildTPKTCOTP(mmsPayload)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "mms" {
		t.Fatalf("expected proto mms, got %s", ev.Proto)
	}
	if ev.Kind != "request" {
		t.Fatalf("expected kind request, got %s", ev.Kind)
	}
	if ev.Attributes["service"] != "read" {
		t.Fatalf("expected service read, got %v", ev.Attributes["service"])
	}
	if ev.Attributes["is_write"] != false {
		t.Fatal("read should not be is_write")
	}
}

func TestMMSDetectsWriteRequest(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	// Build MMS confirmed-request with Write service (tag 0xA5).
	mmsPayload := []byte{
		0xA0, 0x08, // confirmed-request, length 8
		0x02, 0x01, 0x02, // invoke-id = 2
		0xA5, 0x03, // Write service, length 3
		0x30, 0x01, 0x00, // dummy write content
	}

	pkt := buildTPKTCOTP(mmsPayload)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Attributes["service"] != "write" {
		t.Fatalf("expected service write, got %v", ev.Attributes["service"])
	}
	if ev.Attributes["is_write"] != true {
		t.Fatal("write should be is_write")
	}
	if ev.Attributes["is_control"] != true {
		t.Fatal("write should be is_control")
	}
}

func TestMMSDetectsConfirmedResponse(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 102, 12345), time.Now())

	// Build MMS confirmed-response with Read response.
	// Note: confirmed-response PDU tag is 0xA1, service response uses same
	// context tags as request.
	mmsPayload := []byte{
		0xA1, 0x08, // confirmed-response, length 8
		0x02, 0x01, 0x01, // invoke-id = 1
		0xA4, 0x03, // Read response, length 3
		0x30, 0x01, 0x00, // dummy read response content
	}

	pkt := buildTPKTCOTP(mmsPayload)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "response" {
		t.Fatalf("expected kind response, got %s", ev.Kind)
	}
	if ev.Attributes["service"] != "read" {
		t.Fatalf("expected service read, got %v", ev.Attributes["service"])
	}
}

func TestMMSDetectsGetNameList(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	mmsPayload := []byte{
		0xA0, 0x08, // confirmed-request
		0x02, 0x01, 0x01, // invoke-id = 1
		0xA1, 0x03, // GetNameList service (0xA1)
		0x30, 0x01, 0x00,
	}

	pkt := buildTPKTCOTP(mmsPayload)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Attributes["service"] != "get_name_list" {
		t.Fatalf("expected service get_name_list, got %v", events[0].Attributes["service"])
	}
}

func TestMMSConnectionRequest(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	// TPKT + COTP CR (Connection Request).
	pkt := []byte{
		0x03, 0x00, 0x00, 0x0B, // TPKT: version 3, length 11
		0x06,                   // COTP length indicator = 6
		0xE0,                   // COTP CR PDU type
		0x00, 0x00,             // DST ref
		0x00, 0x01,             // SRC ref
		0x00,                   // Class 0
	}

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Kind != "connection_request" {
		t.Fatalf("expected kind connection_request, got %s", events[0].Kind)
	}
}

func TestMMSEmptyPayload(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for empty payload, got %d", len(events))
	}
}

func TestMMSOnFlowEnd(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())
	events, err := dec.OnFlowEnd(state)
	if err != nil {
		t.Fatalf("onflowend: %v", err)
	}
	if events != nil {
		t.Fatalf("expected nil events, got %v", events)
	}
}

func TestMMSInitiateRequest(t *testing.T) {
	dec := NewMMSDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	// MMS initiate-request PDU (tag 0xA8).
	mmsPayload := []byte{
		0xA8, 0x04, // initiate-request
		0x02, 0x01, 0x01, 0x00, // some content
	}
	pkt := buildTPKTCOTP(mmsPayload)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Kind != "initiate_request" {
		t.Fatalf("expected kind initiate_request, got %s", events[0].Kind)
	}
}

// --- GOOSE Tests ---

func TestGOOSESupportsReturnsFalse(t *testing.T) {
	dec := NewGOOSEDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 80), time.Now())
	if dec.Supports(state) {
		t.Fatal("GOOSE decoder should return false (Layer 2 not supported yet)")
	}
	if dec.Supports(nil) {
		t.Fatal("GOOSE decoder should return false for nil state")
	}
}

func TestGOOSEParseFrame(t *testing.T) {
	// Build a minimal GOOSE frame:
	// APPID(2) + Length(2) + Reserved(4) + ASN.1 PDU
	goosePDU := buildGOOSEPDU("testCBRef", "testGoID", "testDatSet", 5, 12)
	frame := make([]byte, 8+len(goosePDU))
	frame[0] = 0x00 // APPID high
	frame[1] = 0x01 // APPID low = 1
	frame[2] = byte((8 + len(goosePDU)) >> 8)
	frame[3] = byte((8 + len(goosePDU)) & 0xFF)
	// Reserved: 4 zero bytes (already zero)
	copy(frame[8:], goosePDU)

	hdr, fields, err := ParseGOOSE(frame)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hdr.APPID != 1 {
		t.Fatalf("expected APPID 1, got %d", hdr.APPID)
	}
	if fields == nil {
		t.Fatal("expected non-nil fields")
	}
	if fields.GoCBRef != "testCBRef" {
		t.Fatalf("expected gocbRef testCBRef, got %q", fields.GoCBRef)
	}
	if fields.GoID != "testGoID" {
		t.Fatalf("expected goID testGoID, got %q", fields.GoID)
	}
	if fields.DatSet != "testDatSet" {
		t.Fatalf("expected datSet testDatSet, got %q", fields.DatSet)
	}
	if fields.StNum != 5 {
		t.Fatalf("expected stNum 5, got %d", fields.StNum)
	}
	if fields.SqNum != 12 {
		t.Fatalf("expected sqNum 12, got %d", fields.SqNum)
	}
}

func TestGOOSEParseTooShort(t *testing.T) {
	_, _, err := ParseGOOSE([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for short frame")
	}
}

func TestGOOSEOnPacketEmitsEvent(t *testing.T) {
	dec := NewGOOSEDecoder()
	state := flow.NewState(mmsKeyFor("10.0.0.1", "10.0.0.2", 12345, 80), time.Now())

	goosePDU := buildGOOSEPDU("cb1", "id1", "ds1", 1, 0)
	frame := make([]byte, 8+len(goosePDU))
	frame[0] = 0x00
	frame[1] = 0x03 // APPID = 3
	frame[2] = byte((8 + len(goosePDU)) >> 8)
	frame[3] = byte((8 + len(goosePDU)) & 0xFF)
	copy(frame[8:], goosePDU)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: frame})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "goose" {
		t.Fatalf("expected proto goose, got %s", ev.Proto)
	}
	if ev.Kind != "publish" {
		t.Fatalf("expected kind publish, got %s", ev.Kind)
	}
	if ev.Attributes["appid"] != "0x0003" {
		t.Fatalf("expected appid 0x0003, got %v", ev.Attributes["appid"])
	}
	if ev.Attributes["gocb_ref"] != "cb1" {
		t.Fatalf("expected gocb_ref cb1, got %v", ev.Attributes["gocb_ref"])
	}
	if ev.Attributes["go_id"] != "id1" {
		t.Fatalf("expected go_id id1, got %v", ev.Attributes["go_id"])
	}
	if ev.Attributes["st_num"] != uint32(1) {
		t.Fatalf("expected st_num 1, got %v", ev.Attributes["st_num"])
	}
	if ev.Attributes["sq_num"] != uint32(0) {
		t.Fatalf("expected sq_num 0, got %v", ev.Attributes["sq_num"])
	}
}

func TestGOOSEOnFlowEnd(t *testing.T) {
	dec := NewGOOSEDecoder()
	events, err := dec.OnFlowEnd(nil)
	if err != nil {
		t.Fatalf("onflowend: %v", err)
	}
	if events != nil {
		t.Fatalf("expected nil events, got %v", events)
	}
}

// --- Test Helpers ---

// buildTPKTCOTP wraps an MMS payload in TPKT + COTP DT headers.
func buildTPKTCOTP(mmsPayload []byte) []byte {
	// COTP DT: length indicator (1) = 2, PDU type = 0xF0, TPDU number = 0x00
	cotpHdr := []byte{0x02, 0xF0, 0x80}
	totalLen := tpktHdrLen + len(cotpHdr) + len(mmsPayload)
	buf := make([]byte, totalLen)
	buf[0] = tpktVersion
	buf[1] = 0x00
	buf[2] = byte(totalLen >> 8)
	buf[3] = byte(totalLen & 0xFF)
	copy(buf[tpktHdrLen:], cotpHdr)
	copy(buf[tpktHdrLen+len(cotpHdr):], mmsPayload)
	return buf
}

// buildGOOSEPDU constructs a minimal ASN.1 GOOSE PDU for testing.
func buildGOOSEPDU(gocbRef, goID, datSet string, stNum, sqNum uint32) []byte {
	// Build individual TLV elements.
	var elements []byte

	// gocbRef (tag 0x80)
	elements = append(elements, buildASN1String(gooseTagGoCBRef, gocbRef)...)
	// datSet (tag 0x82)
	elements = append(elements, buildASN1String(gooseTagDatSet, datSet)...)
	// goID (tag 0x83)
	elements = append(elements, buildASN1String(gooseTagGoID, goID)...)
	// stNum (tag 0x85)
	elements = append(elements, buildASN1Uint32(gooseTagStNum, stNum)...)
	// sqNum (tag 0x86)
	elements = append(elements, buildASN1Uint32(gooseTagSqNum, sqNum)...)

	// Wrap in outer SEQUENCE-like tag (0x61 for goosePdu).
	outer := make([]byte, 2+len(elements))
	outer[0] = 0x61 // goosePdu tag
	outer[1] = byte(len(elements))
	copy(outer[2:], elements)
	return outer
}

func buildASN1String(tag byte, s string) []byte {
	buf := make([]byte, 2+len(s))
	buf[0] = tag
	buf[1] = byte(len(s))
	copy(buf[2:], s)
	return buf
}

func buildASN1Uint32(tag byte, v uint32) []byte {
	// Encode as 4-byte big-endian.
	buf := make([]byte, 6)
	buf[0] = tag
	buf[1] = 4
	buf[2] = byte(v >> 24)
	buf[3] = byte(v >> 16)
	buf[4] = byte(v >> 8)
	buf[5] = byte(v)
	return buf
}
