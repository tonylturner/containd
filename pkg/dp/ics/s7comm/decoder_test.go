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
	binary.BigEndian.PutUint16(hdr[4:6], pduRef)   // PDU reference
	binary.BigEndian.PutUint16(hdr[6:8], paramLen) // parameter length
	binary.BigEndian.PutUint16(hdr[8:10], dataLen) // data length

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

func TestParseTPKTRejectsShortDeclaredLength(t *testing.T) {
	data := []byte{0x03, 0x00, 0x00, 0x02}
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

// buildS7ReadVarParam builds an S7 parameter block for ReadVar with S7ANY items.
func buildS7ReadVarParam(items []S7VarItem) []byte {
	// FC(1) + ItemCount(1) + items
	param := []byte{FuncReadVar, byte(len(items))}
	for _, item := range items {
		// VarSpec(0x12) + AddrLen(10) + SyntaxID(0x10) + TransportSize + Length(2) + DBNumber(2) + Area + Address(3)
		itemBytes := make([]byte, 12)
		itemBytes[0] = 0x12 // variable specification
		itemBytes[1] = 0x0A // address length = 10
		itemBytes[2] = SyntaxS7ANY
		itemBytes[3] = item.TransportSize
		binary.BigEndian.PutUint16(itemBytes[4:6], item.Length)
		binary.BigEndian.PutUint16(itemBytes[6:8], item.DBNumber)
		itemBytes[8] = item.Area
		itemBytes[9] = byte(item.Address >> 16)
		itemBytes[10] = byte(item.Address >> 8)
		itemBytes[11] = byte(item.Address)
		param = append(param, itemBytes...)
	}
	return param
}

// buildS7WriteVarParam builds an S7 parameter block for WriteVar with S7ANY items.
func buildS7WriteVarParam(items []S7VarItem) []byte {
	param := buildS7ReadVarParam(items)
	param[0] = FuncWriteVar
	return param
}

func TestParseS7VarItemsReadDB(t *testing.T) {
	items := []S7VarItem{
		{TransportSize: 0x02, Length: 1, DBNumber: 100, Area: AreaDataBlocks, Address: 0x000018}, // byte 3, bit 0
	}
	param := buildS7ReadVarParam(items)
	s7 := buildS7Header(MsgTypeJob, 0x0001, param, nil)
	hdr, err := ParseS7Header(s7)
	if err != nil {
		t.Fatalf("ParseS7Header: %v", err)
	}
	parsed, count := ParseS7VarItems(s7, hdr)
	if count != 1 {
		t.Fatalf("item_count = %d, want 1", count)
	}
	if len(parsed) != 1 {
		t.Fatalf("parsed %d items, want 1", len(parsed))
	}
	if parsed[0].Area != AreaDataBlocks {
		t.Errorf("area = 0x%02X, want 0x84", parsed[0].Area)
	}
	if parsed[0].DBNumber != 100 {
		t.Errorf("db_number = %d, want 100", parsed[0].DBNumber)
	}
	if parsed[0].Address != 0x18 {
		t.Errorf("address = 0x%06X, want 0x000018", parsed[0].Address)
	}
}

func TestParseS7VarItemsMultiple(t *testing.T) {
	items := []S7VarItem{
		{TransportSize: 0x02, Length: 1, DBNumber: 0, Area: AreaInputs, Address: 0x000008},
		{TransportSize: 0x02, Length: 1, DBNumber: 50, Area: AreaDataBlocks, Address: 0x000020},
	}
	param := buildS7ReadVarParam(items)
	s7 := buildS7Header(MsgTypeJob, 0x0001, param, nil)
	hdr, err := ParseS7Header(s7)
	if err != nil {
		t.Fatalf("ParseS7Header: %v", err)
	}
	parsed, count := ParseS7VarItems(s7, hdr)
	if count != 2 {
		t.Fatalf("item_count = %d, want 2", count)
	}
	if len(parsed) != 2 {
		t.Fatalf("parsed %d items, want 2", len(parsed))
	}
	if parsed[0].Area != AreaInputs {
		t.Errorf("item[0].area = 0x%02X, want 0x81", parsed[0].Area)
	}
	if parsed[1].Area != AreaDataBlocks {
		t.Errorf("item[1].area = 0x%02X, want 0x84", parsed[1].Area)
	}
}

func TestAreaName(t *testing.T) {
	tests := []struct {
		area uint8
		want string
	}{
		{AreaInputs, "inputs"},
		{AreaOutputs, "outputs"},
		{AreaFlags, "flags"},
		{AreaDataBlocks, "data_blocks"},
		{AreaCounter, "counter"},
		{AreaTimer, "timer"},
		{0x99, "unknown_0x99"},
	}
	for _, tc := range tests {
		got := AreaName(tc.area)
		if got != tc.want {
			t.Errorf("AreaName(0x%02X) = %q, want %q", tc.area, got, tc.want)
		}
	}
}

func TestFormatAddress(t *testing.T) {
	tests := []struct {
		addr uint32
		want string
	}{
		{0x000018, "3.0"}, // 24 / 8 = 3, 24 % 8 = 0
		{0x000019, "3.1"}, // 25 / 8 = 3, 25 % 8 = 1
		{0x000000, "0.0"},
		{0x000008, "1.0"}, // 8 / 8 = 1, 8 % 8 = 0
	}
	for _, tc := range tests {
		got := FormatAddress(tc.addr)
		if got != tc.want {
			t.Errorf("FormatAddress(0x%06X) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestDecoderOnPacketReadVarWithItems(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	items := []S7VarItem{
		{TransportSize: 0x02, Length: 1, DBNumber: 100, Area: AreaDataBlocks, Address: 0x000018},
	}
	param := buildS7ReadVarParam(items)
	pkt := buildFullPacket(MsgTypeJob, 0x0001, param, nil)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Attributes["item_count"] != uint8(1) {
		t.Errorf("item_count = %v, want 1", ev.Attributes["item_count"])
	}
	if ev.Attributes["area"] != "data_blocks" {
		t.Errorf("area = %v, want 'data_blocks'", ev.Attributes["area"])
	}
	if ev.Attributes["db_number"] != uint16(100) {
		t.Errorf("db_number = %v, want 100", ev.Attributes["db_number"])
	}
	if ev.Attributes["address"] != "3.0" {
		t.Errorf("address = %v, want '3.0'", ev.Attributes["address"])
	}
	// Read should NOT have safety_critical flag.
	if _, ok := ev.Attributes["safety_critical"]; ok {
		t.Error("read_var should not have safety_critical flag")
	}
}

func TestDecoderOnPacketWriteVarDBSafetyCritical(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	items := []S7VarItem{
		{TransportSize: 0x02, Length: 1, DBNumber: 1, Area: AreaDataBlocks, Address: 0x000000},
	}
	param := buildS7WriteVarParam(items)
	pkt := buildFullPacket(MsgTypeJob, 0x0002, param, nil)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Attributes["safety_critical"] != true {
		t.Error("write to data_blocks should have safety_critical=true")
	}
	if ev.Attributes["is_write"] != true {
		t.Error("is_write should be true for write_var")
	}
}

func TestDecoderOnPacketReadVarInputsNoDBNumber(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 102), time.Now())

	items := []S7VarItem{
		{TransportSize: 0x02, Length: 1, DBNumber: 0, Area: AreaInputs, Address: 0x000008},
	}
	param := buildS7ReadVarParam(items)
	pkt := buildFullPacket(MsgTypeJob, 0x0001, param, nil)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: pkt})
	if err != nil {
		t.Fatalf("OnPacket: %v", err)
	}
	ev := events[0]
	if ev.Attributes["area"] != "inputs" {
		t.Errorf("area = %v, want 'inputs'", ev.Attributes["area"])
	}
	// db_number should NOT be set for non-DB areas.
	if _, ok := ev.Attributes["db_number"]; ok {
		t.Error("db_number should not be set for inputs area")
	}
}
