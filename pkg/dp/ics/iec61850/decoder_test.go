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

