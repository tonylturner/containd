// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cip

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// buildEIPHeader creates a raw EIP encapsulation header with the given command
// and data payload.
func buildEIPHeader(command uint16, sessionHandle uint32, data []byte) []byte {
	buf := make([]byte, 24+len(data))
	binary.LittleEndian.PutUint16(buf[0:2], command)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(data)))
	binary.LittleEndian.PutUint32(buf[4:8], sessionHandle)
	// status = 0, sender context = 0, options = 0
	copy(buf[24:], data)
	return buf
}

// buildSendRRDataPayload creates the data portion of a SendRRData command
// containing a CIP message in an Unconnected Data Item.
func buildSendRRDataPayload(serviceCode uint8, pathSize uint8, path []byte) []byte {
	// CIP message: service code (1) + path size (1) + path (pathSize*2)
	cipLen := 2 + int(pathSize)*2
	cipMsg := make([]byte, cipLen)
	cipMsg[0] = serviceCode
	cipMsg[1] = pathSize
	if len(path) > 0 {
		copy(cipMsg[2:], path)
	}

	// Build items: Null address item + Unconnected Data Item
	// Interface handle (4) + Timeout (2) + Item count (2) = 8
	// Null item: type(2) + len(2) = 4
	// Unconnected data item: type(2) + len(2) + data
	payloadLen := 8 + 4 + 4 + cipLen
	payload := make([]byte, payloadLen)
	// Interface handle = 0
	// Timeout = 0
	binary.LittleEndian.PutUint16(payload[6:8], 2) // item count = 2

	offset := 8
	// Null Address Item (type 0x0000, length 0)
	binary.LittleEndian.PutUint16(payload[offset:offset+2], 0x0000)
	binary.LittleEndian.PutUint16(payload[offset+2:offset+4], 0)
	offset += 4

	// Unconnected Data Item (type 0x00B2)
	binary.LittleEndian.PutUint16(payload[offset:offset+2], 0x00B2)
	binary.LittleEndian.PutUint16(payload[offset+2:offset+4], uint16(cipLen))
	offset += 4
	copy(payload[offset:], cipMsg)

	return payload
}

func TestParseEIPHeader(t *testing.T) {
	data := buildEIPHeader(0x0065, 0x12345678, []byte{0x01, 0x00, 0x00, 0x00})
	hdr, err := ParseEIPHeader(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hdr.Command != 0x0065 {
		t.Fatalf("expected command 0x0065, got 0x%04X", hdr.Command)
	}
	if hdr.SessionHandle != 0x12345678 {
		t.Fatalf("expected session 0x12345678, got 0x%08X", hdr.SessionHandle)
	}
	if hdr.Length != 4 {
		t.Fatalf("expected length 4, got %d", hdr.Length)
	}
	if len(hdr.Data) != 4 {
		t.Fatalf("expected 4 data bytes, got %d", len(hdr.Data))
	}
}

func TestParseEIPHeaderTooShort(t *testing.T) {
	if _, err := ParseEIPHeader([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestParseCIPMessageFromSendRRData(t *testing.T) {
	// Build a SendRRData payload with Read_Tag_Service (0x4C), path = [0x20, 0x02]
	path := []byte{0x20, 0x02}
	payload := buildSendRRDataPayload(0x4C, 1, path)

	cipMsg, err := ParseCIPMessage(payload)
	if err != nil {
		t.Fatalf("parse CIP: %v", err)
	}
	if cipMsg.ServiceCode != 0x4C {
		t.Fatalf("expected service 0x4C, got 0x%02X", cipMsg.ServiceCode)
	}
	if cipMsg.ServiceName != "Read_Tag_Service" {
		t.Fatalf("expected Read_Tag_Service, got %s", cipMsg.ServiceName)
	}
	if cipMsg.IsResponse {
		t.Fatal("expected request, got response")
	}
	if len(cipMsg.Path) != 2 {
		t.Fatalf("expected 2 path bytes, got %d", len(cipMsg.Path))
	}
}

func TestParseCIPMessageResponse(t *testing.T) {
	// Response has bit 0x80 set: 0x4C | 0x80 = 0xCC
	path := []byte{0x20, 0x02}
	payload := buildSendRRDataPayload(0xCC, 1, path)

	cipMsg, err := ParseCIPMessage(payload)
	if err != nil {
		t.Fatalf("parse CIP: %v", err)
	}
	if cipMsg.ServiceCode != 0x4C {
		t.Fatalf("expected base service 0x4C, got 0x%02X", cipMsg.ServiceCode)
	}
	if !cipMsg.IsResponse {
		t.Fatal("expected response")
	}
}

func TestServiceCodeClassification(t *testing.T) {
	// Read services
	for _, code := range []uint8{0x01, 0x0E, 0x4C} {
		if !IsReadService(code) {
			t.Fatalf("expected 0x%02X to be read", code)
		}
		if IsWriteService(code) {
			t.Fatalf("0x%02X should not be write", code)
		}
	}

	// Write services
	for _, code := range []uint8{0x10, 0x4D, 0x4E} {
		if !IsWriteService(code) {
			t.Fatalf("expected 0x%02X to be write", code)
		}
		if IsReadService(code) {
			t.Fatalf("0x%02X should not be read", code)
		}
	}

	// Control services
	if !IsControlService(0x54) {
		t.Fatal("expected 0x54 to be control")
	}
	if IsControlService(0x4C) {
		t.Fatal("0x4C should not be control")
	}

	// Response bit should be masked off
	if !IsReadService(0x4C | 0x80) {
		t.Fatal("response 0xCC should still classify as read")
	}
}

func TestCommandName(t *testing.T) {
	if CommandName(0x0065) != "RegisterSession" {
		t.Fatalf("expected RegisterSession, got %s", CommandName(0x0065))
	}
	if CommandName(0x006F) != "SendRRData" {
		t.Fatalf("expected SendRRData, got %s", CommandName(0x006F))
	}
	name := CommandName(0xFFFF)
	if name == "" {
		t.Fatal("expected non-empty name for unknown command")
	}
}

func TestServiceName(t *testing.T) {
	if ServiceName(0x4C) != "Read_Tag_Service" {
		t.Fatalf("expected Read_Tag_Service, got %s", ServiceName(0x4C))
	}
	// Response bit masked
	if ServiceName(0xCC) != "Read_Tag_Service" {
		t.Fatalf("expected Read_Tag_Service for response, got %s", ServiceName(0xCC))
	}
}

func TestDecoderSupportsTCP44818(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 44818, 6), time.Now())
	if !dec.Supports(state) {
		t.Fatal("should support TCP port 44818")
	}
}

func TestDecoderSupportsUDP2222(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 2222, 17), time.Now())
	if !dec.Supports(state) {
		t.Fatal("should support UDP port 2222")
	}
}

func TestDecoderDoesNotSupportOtherPorts(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 80, 6), time.Now())
	if dec.Supports(state) {
		t.Fatal("should not support TCP port 80")
	}
}

func TestDecoderSupportsNil(t *testing.T) {
	dec := NewDecoder()
	if dec.Supports(nil) {
		t.Fatal("should not support nil state")
	}
}

func TestDecoderOnPacketSendRRData(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 44818, 6), time.Now())

	// Build a full SendRRData packet with Read_Tag_Service
	path := []byte{0x20, 0x02}
	cipPayload := buildSendRRDataPayload(0x4C, 1, path)
	raw := buildEIPHeader(0x006F, 0x00000001, cipPayload)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "cip" {
		t.Fatalf("expected proto cip, got %s", ev.Proto)
	}
	if ev.Kind != "request" {
		t.Fatalf("expected kind request, got %s", ev.Kind)
	}
	if ev.Attributes["command"] != "SendRRData" {
		t.Fatalf("expected command SendRRData, got %v", ev.Attributes["command"])
	}
	if ev.Attributes["service_code"] != uint8(0x4C) {
		t.Fatalf("expected service_code 0x4C, got %v", ev.Attributes["service_code"])
	}
	if ev.Attributes["is_write"] != false {
		t.Fatal("Read_Tag_Service should not be is_write")
	}
	if ev.Attributes["cip_path"] != "2002" {
		t.Fatalf("expected cip_path 2002, got %v", ev.Attributes["cip_path"])
	}
}

func TestDecoderOnPacketRegisterSession(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 44818, 6), time.Now())

	// RegisterSession command (0x0065) with minimal data
	data := []byte{0x01, 0x00, 0x00, 0x00} // protocol version + options
	raw := buildEIPHeader(0x0065, 0x00000000, data)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "cip" {
		t.Fatalf("expected proto cip, got %s", ev.Proto)
	}
	if ev.Kind != "session" {
		t.Fatalf("expected kind session, got %s", ev.Kind)
	}
	if ev.Attributes["command"] != "RegisterSession" {
		t.Fatalf("expected command RegisterSession, got %v", ev.Attributes["command"])
	}
}

func TestDecoderOnPacketResponse(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 44818, 12345, 6), time.Now())

	// Build a SendRRData response with Write_Tag_Service response (0x4D | 0x80 = 0xCD)
	cipPayload := buildSendRRDataPayload(0xCD, 0, nil)
	raw := buildEIPHeader(0x006F, 0x00000001, cipPayload)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
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
	if ev.Attributes["is_write"] != true {
		t.Fatal("Write_Tag_Service response should be is_write")
	}
}

func TestDecoderOnPacketNilPayload(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 44818, 6), time.Now())

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for empty payload, got %d", len(events))
	}
}

func TestDecoderOnFlowEnd(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 44818, 6), time.Now())
	events, err := dec.OnFlowEnd(state)
	if err != nil {
		t.Fatalf("onflowend: %v", err)
	}
	if events != nil {
		t.Fatalf("expected nil events, got %v", events)
	}
}
