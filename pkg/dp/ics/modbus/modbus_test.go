package modbus

import (
	"testing"
	"time"

	"github.com/containd/containd/pkg/dp/dpi"
	"github.com/containd/containd/pkg/dp/flow"
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
