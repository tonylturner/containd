// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package modbus

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestParseTCPFrameReadHoldingRegisters(t *testing.T) {
	// TID=1, PID=0, LEN=6, Unit=1, FC=3, Addr=0x0000, Qty=0x0002
	raw := []byte{
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x06,
		0x01,
		0x03,
		0x00, 0x00,
		0x00, 0x02,
	}
	f, err := ParseTCPFrame(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.TransactionID != 1 || f.UnitID != 1 || f.FunctionCode != 3 {
		t.Fatalf("unexpected header: %+v", f)
	}
	if len(f.PDU) != 4 {
		t.Fatalf("unexpected pdu length %d", len(f.PDU))
	}
	if IsWriteFunctionCode(f.FunctionCode) {
		t.Fatalf("fc=3 should not be write")
	}
}

func TestParseTCPFrameTooShort(t *testing.T) {
	if _, err := ParseTCPFrame([]byte{0x00}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestIsWriteFunctionCode(t *testing.T) {
	if !IsWriteFunctionCode(16) {
		t.Fatalf("fc=16 should be write")
	}
	if IsWriteFunctionCode(4) {
		t.Fatalf("fc=4 should not be write")
	}
}

func TestDecoderEmitsEvent(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 502), time.Now())
	raw := []byte{
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x06,
		0x01,
		0x03,
		0x00, 0x00,
		0x00, 0x02,
	}
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 || events[0].Proto != "modbus" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestDecoderSupportsAndPorts(t *testing.T) {
	dec := NewDecoder()
	tcpPorts, udpPorts := dec.Ports()
	if len(tcpPorts) != 1 || tcpPorts[0] != 502 || len(udpPorts) != 0 {
		t.Fatalf("Ports() = tcp=%v udp=%v", tcpPorts, udpPorts)
	}

	if dec.Supports(nil) {
		t.Fatal("Supports(nil) should be false")
	}
	if dec.Supports(flow.NewState(flow.Key{Proto: 17, SrcPort: 12345, DstPort: 502}, time.Now())) {
		t.Fatal("Supports(non-TCP) should be false")
	}
	if !dec.Supports(flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 502), time.Now())) {
		t.Fatal("Supports(modbus tcp flow) should be true")
	}
}

func TestDecoderExceptionAndDiagnosticsEvents(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 502), time.Now())

	exceptionFrame := []byte{
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x03,
		0x01,
		0x83,
		0x02,
	}
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: exceptionFrame})
	if err != nil {
		t.Fatalf("OnPacket(exception): %v", err)
	}
	if len(events) != 1 || events[0].Kind != "exception" {
		t.Fatalf("unexpected exception events: %+v", events)
	}
	if got := events[0].Attributes["exception_description"]; got != "illegal_data_address" {
		t.Fatalf("exception_description = %v", got)
	}
	if got := events[0].Attributes["is_write"]; got != false {
		t.Fatalf("is_write(exception) = %v", got)
	}

	diagFrame := []byte{
		0x00, 0x02,
		0x00, 0x00,
		0x00, 0x06,
		0x01,
		0x08,
		0x00, 0x01,
		0x00, 0x00,
	}
	events, err = dec.OnPacket(state, &dpi.ParsedPacket{Payload: diagFrame})
	if err != nil {
		t.Fatalf("OnPacket(diagnostics): %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("unexpected diagnostics events: %+v", events)
	}
	if got := events[0].Attributes["sub_function_name"]; got != "restart_comm" {
		t.Fatalf("sub_function_name = %v", got)
	}
	if got := events[0].Attributes["is_write"]; got != true {
		t.Fatalf("is_write(diagnostics) = %v", got)
	}
}

func TestDecoderHelpers(t *testing.T) {
	dec := NewDecoder()
	if events, err := dec.OnFlowEnd(flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 502), time.Now())); err != nil || events != nil {
		t.Fatalf("OnFlowEnd() = %v, %v", events, err)
	}

	if got := exceptionName(11); got != "gateway_target_failed" {
		t.Fatalf("exceptionName(11) = %q", got)
	}
	if got := exceptionName(99); got != "unknown" {
		t.Fatalf("exceptionName(99) = %q", got)
	}
	if got := diagSubFunctionName(4); got != "force_listen_only" {
		t.Fatalf("diagSubFunctionName(4) = %q", got)
	}
	if got := diagSubFunctionName(999); got != "unknown" {
		t.Fatalf("diagSubFunctionName(999) = %q", got)
	}
}
