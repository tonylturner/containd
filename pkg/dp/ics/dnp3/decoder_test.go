// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// buildTestFrame constructs a valid DNP3 frame with correct CRCs for testing.
func buildTestFrame(length, control uint8, dest, src uint16, userData []byte) []byte {
	// Header: start(2) + length(1) + control(1) + dest(2) + src(2) = 8 bytes.
	header := make([]byte, 8)
	header[0] = 0x05
	header[1] = 0x64
	header[2] = length
	header[3] = control
	binary.LittleEndian.PutUint16(header[4:6], dest)
	binary.LittleEndian.PutUint16(header[6:8], src)

	// Compute header CRC.
	hcrc := crc16DNP3(header)
	hcrcBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(hcrcBytes, hcrc)

	frame := append(header, hcrcBytes...)

	// Add data blocks with CRCs (up to 16 data bytes per block).
	remaining := userData
	for len(remaining) > 0 {
		blockSize := len(remaining)
		if blockSize > 16 {
			blockSize = 16
		}
		block := remaining[:blockSize]
		remaining = remaining[blockSize:]
		dcrc := crc16DNP3(block)
		dcrcBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(dcrcBytes, dcrc)
		frame = append(frame, block...)
		frame = append(frame, dcrcBytes...)
	}
	return frame
}

func TestParseFrameReadRequest(t *testing.T) {
	// Transport(0xC0=FIR+FIN) + AppControl(0xC0) + FuncCode(0x01=Read) + ObjGroup(30) + Var(2)
	userData := []byte{0xC0, 0xC0, 0x01, 0x1E, 0x02}
	// length = 5 (ctrl+dest+src) + len(userData) = 10
	raw := buildTestFrame(0x0A, 0xC0, 0x0001, 0x0002, userData)

	frame, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if frame.Destination != 1 {
		t.Errorf("destination = %d, want 1", frame.Destination)
	}
	if frame.Source != 2 {
		t.Errorf("source = %d, want 2", frame.Source)
	}
	if frame.FunctionCode != FuncRead {
		t.Errorf("function code = 0x%02X, want 0x01", frame.FunctionCode)
	}
	if frame.ObjectGroup() != 30 {
		t.Errorf("object group = %d, want 30", frame.ObjectGroup())
	}
}

func TestParseFrameResponse(t *testing.T) {
	// Transport(0xC0) + AppControl(0xC0) + FuncCode(0x81=Response) + IIN(0x00,0x00) + ObjGroup(30) + Var(2)
	userData := []byte{0xC0, 0xC0, 0x81, 0x00, 0x00, 0x1E, 0x02}
	raw := buildTestFrame(0x0C, 0x44, 0x0002, 0x0001, userData)

	frame, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if frame.FunctionCode != FuncResponse {
		t.Errorf("function code = 0x%02X, want 0x81", frame.FunctionCode)
	}
	if !IsResponse(frame.FunctionCode) {
		t.Error("expected IsResponse to be true for 0x81")
	}
	if frame.ObjectGroup() != 30 {
		t.Errorf("object group = %d, want 30", frame.ObjectGroup())
	}
}

func TestParseFrameTooShort(t *testing.T) {
	_, err := ParseFrame([]byte{0x05, 0x64})
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestParseFrameInvalidStart(t *testing.T) {
	data := make([]byte, 10)
	data[0] = 0xFF
	data[1] = 0xFF
	_, err := ParseFrame(data)
	if err != ErrInvalidStart {
		t.Errorf("expected ErrInvalidStart, got %v", err)
	}
}

func TestParseFrameBadCRC(t *testing.T) {
	header := []byte{0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00}
	// Append bad CRC.
	data := append(header, 0xFF, 0xFF)
	_, err := ParseFrame(data)
	if err != ErrBadHeaderCRC {
		t.Errorf("expected ErrBadHeaderCRC, got %v", err)
	}
}

func TestIsWriteFunctionCode(t *testing.T) {
	writeCodes := []uint8{FuncWrite, FuncSelect, FuncOperate, FuncDirectOperate,
		FuncDirectOperateNoAck, FuncColdRestart, FuncWarmRestart,
		FuncStopApplication, FuncSaveConfiguration}
	for _, fc := range writeCodes {
		if !IsWriteFunctionCode(fc) {
			t.Errorf("expected fc=0x%02X to be write", fc)
		}
	}
	readCodes := []uint8{FuncConfirm, FuncRead, FuncResponse, FuncUnsolicitedResponse}
	for _, fc := range readCodes {
		if IsWriteFunctionCode(fc) {
			t.Errorf("expected fc=0x%02X to NOT be write", fc)
		}
	}
}

func TestIsControlFunctionCode(t *testing.T) {
	if !IsControlFunctionCode(FuncOperate) {
		t.Error("operate should be control")
	}
	if IsControlFunctionCode(FuncRead) {
		t.Error("read should not be control")
	}
	if IsControlFunctionCode(FuncWrite) {
		t.Error("write should not be control")
	}
}

func TestFunctionCodeName(t *testing.T) {
	if FunctionCodeName(FuncRead) != "read" {
		t.Errorf("expected 'read', got %q", FunctionCodeName(FuncRead))
	}
	if FunctionCodeName(FuncResponse) != "response" {
		t.Errorf("expected 'response', got %q", FunctionCodeName(FuncResponse))
	}
	name := FunctionCodeName(0xFF)
	if name != "unknown_0xff" {
		t.Errorf("expected 'unknown_0xff', got %q", name)
	}
}

func TestDecoderSupportsPort20000(t *testing.T) {
	dec := NewDecoder()
	// Should match port 20000 on TCP.
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 20000), time.Now())
	if !dec.Supports(state) {
		t.Error("expected Supports to return true for DstPort=20000")
	}
	// Should match source port 20000.
	state2 := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 20000, 54321), time.Now())
	if !dec.Supports(state2) {
		t.Error("expected Supports to return true for SrcPort=20000")
	}
	// Should not match other ports.
	state3 := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 502), time.Now())
	if dec.Supports(state3) {
		t.Error("expected Supports to return false for port 502")
	}
	// Should not match nil state.
	if dec.Supports(nil) {
		t.Error("expected Supports to return false for nil state")
	}
}

func TestDecoderOnPacketReadRequest(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 20000), time.Now())

	// Build a read request frame.
	userData := []byte{0xC0, 0xC0, 0x01, 0x1E, 0x02}
	raw := buildTestFrame(0x0A, 0xC0, 0x0001, 0x0002, userData)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "dnp3" {
		t.Errorf("proto = %q, want 'dnp3'", ev.Proto)
	}
	if ev.Kind != "request" {
		t.Errorf("kind = %q, want 'request'", ev.Kind)
	}
	if ev.Attributes["function_code"] != uint8(0x01) {
		t.Errorf("function_code = %v, want 0x01", ev.Attributes["function_code"])
	}
	if ev.Attributes["function_name"] != "read" {
		t.Errorf("function_name = %v, want 'read'", ev.Attributes["function_name"])
	}
	if ev.Attributes["is_write"] != false {
		t.Error("is_write should be false for read")
	}
	if ev.Attributes["is_control"] != false {
		t.Error("is_control should be false for read")
	}
	if ev.Attributes["source_address"] != uint16(2) {
		t.Errorf("source_address = %v, want 2", ev.Attributes["source_address"])
	}
	if ev.Attributes["destination_address"] != uint16(1) {
		t.Errorf("destination_address = %v, want 1", ev.Attributes["destination_address"])
	}
}

func TestDecoderOnPacketResponse(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.2", "10.0.0.1", 20000, 12345), time.Now())

	userData := []byte{0xC0, 0xC0, 0x81, 0x00, 0x00, 0x1E, 0x02}
	raw := buildTestFrame(0x0C, 0x44, 0x0002, 0x0001, userData)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Kind != "response" {
		t.Errorf("kind = %q, want 'response'", events[0].Kind)
	}
}

func TestDecoderOnPacketWriteControl(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 20000), time.Now())

	// Operate (0x04) with CROB group (12).
	userData := []byte{0xC0, 0xC0, 0x04, 0x0C, 0x01}
	raw := buildTestFrame(0x0A, 0xC0, 0x0001, 0x0002, userData)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Attributes["is_write"] != true {
		t.Error("is_write should be true for operate")
	}
	if ev.Attributes["is_control"] != true {
		t.Error("is_control should be true for operate")
	}
	if ev.Attributes["object_group"] != uint8(12) {
		t.Errorf("object_group = %v, want 12", ev.Attributes["object_group"])
	}
}

func TestDecoderOnPacketNilPayload(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 20000), time.Now())

	events, err := dec.OnPacket(state, nil)
	if err != nil || events != nil {
		t.Errorf("expected nil, nil for nil packet; got %v, %v", events, err)
	}
	events, err = dec.OnPacket(state, &dpi.ParsedPacket{})
	if err != nil || events != nil {
		t.Errorf("expected nil, nil for empty payload; got %v, %v", events, err)
	}
}

func TestDecoderOnFlowEnd(t *testing.T) {
	dec := NewDecoder()
	events, err := dec.OnFlowEnd(nil)
	if err != nil || events != nil {
		t.Errorf("expected nil, nil; got %v, %v", events, err)
	}
}
