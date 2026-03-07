// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package s7comm

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// buildTPKT wraps payload in a TPKT header (version=0x03, reserved=0x00).
func buildTPKT(payload []byte) []byte {
	total := 4 + len(payload)
	buf := make([]byte, total)
	buf[0] = 0x03
	buf[1] = 0x00
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	copy(buf[4:], payload)
	return buf
}

// buildCOTPData builds a minimal COTP DT header (length=2, PDU type=0x0F, TPDU=0x80).
func buildCOTPData(payload []byte) []byte {
	// COTP DT header: length(1) + pdu_type(1) + tpdu_number_eot(1) = 3 bytes, length field = 2
	hdr := []byte{0x02, 0x0F, 0x80}
	return append(hdr, payload...)
}

// buildCOTPCR builds a minimal COTP Connection Request header.
func buildCOTPCR() []byte {
	// Minimal CR: length=6, pdu_type=0xE0, dst_ref(2), src_ref(2), class(1)
	return []byte{0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}
}

// buildCOTPCC builds a minimal COTP Connection Confirm header.
func buildCOTPCC() []byte {
	return []byte{0x06, 0xD0, 0x00, 0x00, 0x00, 0x01, 0x00}
}

// buildS7Header builds an S7comm header with optional parameter bytes.
func buildS7Header(msgType uint8, pduRef uint16, paramData []byte, s7data []byte) []byte {
	paramLen := uint16(len(paramData))
	dataLen := uint16(len(s7data))

	var hdr []byte
	if msgType == MsgTypeAckData {
		// 12-byte header for Ack-Data.
		hdr = make([]byte, 12)
		hdr[10] = 0x00 // error class
		hdr[11] = 0x00 // error code
	} else {
		hdr = make([]byte, 10)
	}
	hdr[0] = 0x32 // protocol ID
	hdr[1] = msgType
	binary.BigEndian.PutUint16(hdr[2:4], 0x0000)   // reserved
	binary.BigEndian.PutUint16(hdr[4:6], pduRef)    // PDU reference
	binary.BigEndian.PutUint16(hdr[6:8], paramLen)  // parameter length
	binary.BigEndian.PutUint16(hdr[8:10], dataLen)  // data length

	result := append(hdr, paramData...)
	result = append(result, s7data...)
	return result
}

// buildFullPacket wraps S7 header inside COTP DT inside TPKT.
func buildFullPacket(msgType uint8, pduRef uint16, paramData []byte, s7data []byte) []byte {
	s7 := buildS7Header(msgType, pduRef, paramData, s7data)
	cotp := buildCOTPData(s7)
	return buildTPKT(cotp)
}

func TestParseTPKTValid(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	pkt := buildTPKT(payload)
	hdr, rem, err := ParseTPKT(pkt)
	if err != nil {
		t.Fatalf("ParseTPKT: %v", err)
	}
	if hdr.Version != 0x03 {
		t.Errorf("version = 0x%02X, want 0x03", hdr.Version)
	}
	if hdr.Length != uint16(len(pkt)) {
		t.Errorf("length = %d, want %d", hdr.Length, len(pkt))
	}
	if len(rem) != 3 {
		t.Errorf("remaining = %d bytes, want 3", len(rem))
	}
}

func TestParseTPKTTooShort(t *testing.T) {
	_, _, err := ParseTPKT([]byte{0x03, 0x00})
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestParseTPKTInvalidVersion(t *testing.T) {
	data := []byte{0x04, 0x00, 0x00, 0x07, 0x01, 0x02, 0x03}
	_, _, err := ParseTPKT(data)
	if err != ErrInvalidTPKT {
		t.Errorf("expected ErrInvalidTPKT, got %v", err)
	}
}

func TestParseCOTPValid(t *testing.T) {
	// length=2, pdu_type=0x0F, tpdu=0x80, then payload 0xAA
	data := []byte{0x02, 0x0F, 0x80, 0xAA}
	hdr, rem, err := ParseCOTP(data)
	if err != nil {
		t.Fatalf("ParseCOTP: %v", err)
	}
	if hdr.PDUType != 0x0F {
		t.Errorf("PDUType = 0x%02X, want 0x0F", hdr.PDUType)
	}
	if len(rem) != 1 || rem[0] != 0xAA {
		t.Errorf("remaining = %v, want [0xAA]", rem)
	}
}

func TestParseCOTPTooShort(t *testing.T) {
	_, _, err := ParseCOTP([]byte{0x02})
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestParseS7HeaderJob(t *testing.T) {
	s7 := buildS7Header(MsgTypeJob, 0x0100, []byte{FuncReadVar}, nil)
	hdr, err := ParseS7Header(s7)
	if err != nil {
		t.Fatalf("ParseS7Header: %v", err)
	}
	if hdr.ProtocolID != 0x32 {
		t.Errorf("ProtocolID = 0x%02X, want 0x32", hdr.ProtocolID)
	}
	if hdr.MessageType != MsgTypeJob {
		t.Errorf("MessageType = 0x%02X, want 0x01", hdr.MessageType)
	}
	if hdr.PDUReference != 0x0100 {
		t.Errorf("PDUReference = 0x%04X, want 0x0100", hdr.PDUReference)
	}
	if hdr.ParamLength != 1 {
		t.Errorf("ParamLength = %d, want 1", hdr.ParamLength)
	}
}

func TestParseS7HeaderAckData(t *testing.T) {
	s7 := buildS7Header(MsgTypeAckData, 0x0001, []byte{FuncReadVar}, nil)
	s7[10] = 0x81 // error class
	s7[11] = 0x04 // error code
	hdr, err := ParseS7Header(s7)
	if err != nil {
		t.Fatalf("ParseS7Header: %v", err)
	}
	if hdr.MessageType != MsgTypeAckData {
		t.Errorf("MessageType = 0x%02X, want 0x03", hdr.MessageType)
	}
	if hdr.ErrorClass != 0x81 {
		t.Errorf("ErrorClass = 0x%02X, want 0x81", hdr.ErrorClass)
	}
	if hdr.ErrorCode != 0x04 {
		t.Errorf("ErrorCode = 0x%02X, want 0x04", hdr.ErrorCode)
	}
}

func TestParseS7HeaderTooShort(t *testing.T) {
	_, err := ParseS7Header([]byte{0x32, 0x01, 0x00})
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestParseS7HeaderInvalidProto(t *testing.T) {
	data := make([]byte, 10)
	data[0] = 0x33 // wrong protocol ID
	_, err := ParseS7Header(data)
	if err != ErrInvalidS7Proto {
		t.Errorf("expected ErrInvalidS7Proto, got %v", err)
	}
}

func TestFunctionCodeName(t *testing.T) {
	tests := []struct {
		fc   uint8
		want string
	}{
		{FuncReadVar, "read_var"},
		{FuncWriteVar, "write_var"},
		{FuncPLCControl, "plc_control"},
		{FuncPLCStop, "plc_stop"},
		{FuncSetupCommunication, "setup_communication"},
		{0xFF, "unknown_0xff"},
	}
	for _, tc := range tests {
		got := FunctionCodeName(tc.fc)
		if got != tc.want {
			t.Errorf("FunctionCodeName(0x%02X) = %q, want %q", tc.fc, got, tc.want)
		}
	}
}

func TestIsWriteFunctionCode(t *testing.T) {
	writeCodes := []uint8{FuncWriteVar, FuncRequestDownload, FuncDownloadBlock,
		FuncDownloadEnded, FuncPLCControl, FuncPLCStop}
	for _, fc := range writeCodes {
		if !IsWriteFunctionCode(fc) {
			t.Errorf("expected fc=0x%02X to be write", fc)
		}
	}
	readCodes := []uint8{FuncReadVar, FuncStartUpload, FuncUpload, FuncEndUpload,
		FuncSetupCommunication, FuncCPUServices}
	for _, fc := range readCodes {
		if IsWriteFunctionCode(fc) {
			t.Errorf("expected fc=0x%02X to NOT be write", fc)
		}
	}
}

func TestIsControlFunctionCode(t *testing.T) {
	if !IsControlFunctionCode(FuncPLCControl) {
		t.Error("plc_control should be control")
	}
	if !IsControlFunctionCode(FuncPLCStop) {
		t.Error("plc_stop should be control")
	}
	if IsControlFunctionCode(FuncReadVar) {
		t.Error("read_var should not be control")
	}
	if IsControlFunctionCode(FuncWriteVar) {
		t.Error("write_var should not be control (write but not control)")
	}
}

func TestMessageTypeName(t *testing.T) {
	if MessageTypeName(MsgTypeJob) != "job" {
		t.Errorf("expected 'job', got %q", MessageTypeName(MsgTypeJob))
	}
	if MessageTypeName(MsgTypeAckData) != "ack_data" {
		t.Errorf("expected 'ack_data', got %q", MessageTypeName(MsgTypeAckData))
	}
	name := MessageTypeName(0xFF)
	if name != "unknown_0xff" {
		t.Errorf("expected 'unknown_0xff', got %q", name)
	}
}

func TestDecoderSupportsPort102(t *testing.T) {
	dec := NewDecoder()
	// Should match destination port 102 on TCP.
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())
	if !dec.Supports(state) {
		t.Error("expected Supports to return true for DstPort=102")
	}
	// Should match source port 102.
	state2 := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 102, 54321), time.Now())
	if !dec.Supports(state2) {
		t.Error("expected Supports to return true for SrcPort=102")
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

func TestDecoderOnPacketReadVarRequest(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	pkt := buildFullPacket(MsgTypeJob, 0x0001, []byte{FuncReadVar}, nil)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "s7comm" {
		t.Errorf("proto = %q, want 's7comm'", ev.Proto)
	}
	if ev.Kind != "request" {
		t.Errorf("kind = %q, want 'request'", ev.Kind)
	}
	if ev.Attributes["function_code"] != uint8(FuncReadVar) {
		t.Errorf("function_code = %v, want 0x04", ev.Attributes["function_code"])
	}
	if ev.Attributes["function_name"] != "read_var" {
		t.Errorf("function_name = %v, want 'read_var'", ev.Attributes["function_name"])
	}
	if ev.Attributes["is_write"] != false {
		t.Error("is_write should be false for read_var")
	}
	if ev.Attributes["is_control"] != false {
		t.Error("is_control should be false for read_var")
	}
}

func TestDecoderOnPacketWriteVarRequest(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	pkt := buildFullPacket(MsgTypeJob, 0x0002, []byte{FuncWriteVar}, nil)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Attributes["is_write"] != true {
		t.Error("is_write should be true for write_var")
	}
	if ev.Attributes["is_control"] != false {
		t.Error("is_control should be false for write_var")
	}
}

func TestDecoderOnPacketPLCStop(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	pkt := buildFullPacket(MsgTypeJob, 0x0003, []byte{FuncPLCStop}, nil)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Attributes["is_write"] != true {
		t.Error("is_write should be true for plc_stop")
	}
	if ev.Attributes["is_control"] != true {
		t.Error("is_control should be true for plc_stop")
	}
	if ev.Attributes["function_name"] != "plc_stop" {
		t.Errorf("function_name = %v, want 'plc_stop'", ev.Attributes["function_name"])
	}
}

func TestDecoderOnPacketAckDataResponse(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.2", "10.0.0.1", 102, 12345), time.Now())

	pkt := buildFullPacket(MsgTypeAckData, 0x0001, []byte{FuncReadVar}, nil)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "response" {
		t.Errorf("kind = %q, want 'response'", ev.Kind)
	}
	if ev.Attributes["error_class"] == nil {
		t.Error("expected error_class attribute for ack_data")
	}
	if ev.Attributes["error_code"] == nil {
		t.Error("expected error_code attribute for ack_data")
	}
}

func TestDecoderOnPacketCOTPConnectionRequest(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	cr := buildCOTPCR()
	pkt := buildTPKT(cr)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "s7comm" {
		t.Errorf("proto = %q, want 's7comm'", ev.Proto)
	}
	if ev.Kind != "connection" {
		t.Errorf("kind = %q, want 'connection'", ev.Kind)
	}
}

func TestDecoderOnPacketCOTPConnectionConfirm(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.2", "10.0.0.1", 102, 12345), time.Now())

	cc := buildCOTPCC()
	pkt := buildTPKT(cc)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Kind != "connection" {
		t.Errorf("kind = %q, want 'connection'", events[0].Kind)
	}
}

func TestDecoderOnPacketNilPayload(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

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

func TestS7ParamFunctionCode(t *testing.T) {
	s7 := buildS7Header(MsgTypeJob, 0x0001, []byte{FuncWriteVar, 0x01}, nil)
	hdr, err := ParseS7Header(s7)
	if err != nil {
		t.Fatalf("ParseS7Header: %v", err)
	}
	fc, ok := S7ParamFunctionCode(s7, hdr)
	if !ok {
		t.Fatal("expected function code to be present")
	}
	if fc != FuncWriteVar {
		t.Errorf("function_code = 0x%02X, want 0x05", fc)
	}
}

func TestS7ParamFunctionCodeNoParams(t *testing.T) {
	s7 := buildS7Header(MsgTypeJob, 0x0001, nil, nil)
	hdr, err := ParseS7Header(s7)
	if err != nil {
		t.Fatalf("ParseS7Header: %v", err)
	}
	_, ok := S7ParamFunctionCode(s7, hdr)
	if ok {
		t.Error("expected no function code when param length is 0")
	}
}
