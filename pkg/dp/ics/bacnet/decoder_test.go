// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package bacnet

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestParseFrameReadProperty(t *testing.T) {
	// BVLC: type=0x81, func=0x0A (Original-Unicast), len=17
	// NPDU: version=0x01, control=0x00 (has APDU, no routing)
	// APDU: confirmed-request (0x00), max-segs/resp=0x05, invoke-id=0x01, service=12 (ReadProperty)
	raw := []byte{
		0x81, 0x0A, 0x00, 0x11, // BVLC
		0x01, 0x00,             // NPDU
		0x00, 0x05, 0x01, 0x0C, // APDU: confirmed-request, service=ReadProperty
		0x0C, 0x02, 0x00, 0x00, 0x01, 0x19, 0x55, // some APDU payload
	}
	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.BVLCType != 0x81 {
		t.Fatalf("unexpected bvlc type: 0x%02x", f.BVLCType)
	}
	if f.BVLCFunction != BVLCOriginalUnicast {
		t.Fatalf("unexpected bvlc function: 0x%02x", f.BVLCFunction)
	}
	if !f.HasAPDU {
		t.Fatal("expected APDU to be present")
	}
	if f.PDUType != PDUConfirmedRequest {
		t.Fatalf("unexpected pdu type: %d", f.PDUType)
	}
	if f.ServiceChoice != ServiceReadProperty {
		t.Fatalf("unexpected service choice: %d", f.ServiceChoice)
	}
	if IsWriteService(f.ServiceChoice) {
		t.Fatal("ReadProperty should not be a write service")
	}
}

func TestParseFrameWhoIs(t *testing.T) {
	// BVLC: type=0x81, func=0x0B (Original-Broadcast), len=8
	// NPDU: version=0x01, control=0x00
	// APDU: unconfirmed-request (0x10), service=8 (WhoIs)
	raw := []byte{
		0x81, 0x0B, 0x00, 0x08,
		0x01, 0x00,
		0x10, 0x08,
	}
	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.PDUType != PDUUnconfirmedRequest {
		t.Fatalf("unexpected pdu type: %d", f.PDUType)
	}
	if f.ServiceChoice != ServiceWhoIs {
		t.Fatalf("unexpected service: %d", f.ServiceChoice)
	}
	if !IsDiscoveryService(f.PDUType, f.ServiceChoice) {
		t.Fatal("WhoIs should be discovery")
	}
	if ServiceName(f.PDUType, f.ServiceChoice) != "who-is" {
		t.Fatalf("unexpected service name: %s", ServiceName(f.PDUType, f.ServiceChoice))
	}
}

func TestParseFrameWriteProperty(t *testing.T) {
	// BVLC: type=0x81, func=0x0A, len=12
	// NPDU: version=0x01, control=0x00
	// APDU: confirmed-request, service=15 (WriteProperty)
	raw := []byte{
		0x81, 0x0A, 0x00, 0x0C,
		0x01, 0x00,
		0x00, 0x05, 0x01, 0x0F,
		0xAA, 0xBB,
	}
	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.ServiceChoice != ServiceWriteProperty {
		t.Fatalf("unexpected service: %d", f.ServiceChoice)
	}
	if !IsWriteService(f.ServiceChoice) {
		t.Fatal("WriteProperty should be a write service")
	}
}

func TestParseFrameTooShort(t *testing.T) {
	if _, err := ParseFrame([]byte{0x81}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseFrameInvalidType(t *testing.T) {
	raw := []byte{0x82, 0x0A, 0x00, 0x04}
	_, err := ParseFrame(raw)
	if err == nil {
		t.Fatal("expected error for invalid BVLC type")
	}
}

func TestServiceName(t *testing.T) {
	tests := []struct {
		pdu     uint8
		service uint8
		want    string
	}{
		{PDUUnconfirmedRequest, ServiceIAm, "i-am"},
		{PDUUnconfirmedRequest, ServiceWhoIs, "who-is"},
		{PDUUnconfirmedRequest, ServiceWhoHas, "who-has"},
		{PDUConfirmedRequest, ServiceReadProperty, "read-property"},
		{PDUConfirmedRequest, ServiceWriteProperty, "write-property"},
		{PDUConfirmedRequest, ServiceReadPropertyMultiple, "read-property-multiple"},
		{PDUConfirmedRequest, ServiceWritePropertyMultiple, "write-property-multiple"},
		{PDUConfirmedRequest, ServiceSubscribeCOV, "subscribe-cov"},
		{PDUConfirmedRequest, 99, "service-99"},
	}
	for _, tt := range tests {
		got := ServiceName(tt.pdu, tt.service)
		if got != tt.want {
			t.Errorf("ServiceName(%d, %d) = %q, want %q", tt.pdu, tt.service, got, tt.want)
		}
	}
}

func TestDecoderSupports(t *testing.T) {
	dec := NewDecoder()
	// UDP port 47808 — should support.
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 47808), time.Now())
	if !dec.Supports(state) {
		t.Fatal("expected Supports=true for UDP port 47808")
	}
	// TCP port 47808 — should NOT support (BACnet/IP is UDP).
	tcpKey := flow.Key{
		SrcIP:   state.Key.SrcIP,
		DstIP:   state.Key.DstIP,
		SrcPort: 12345,
		DstPort: 47808,
		Proto:   6,
		Dir:     flow.DirForward,
	}
	tcpState := flow.NewState(tcpKey, time.Now())
	if dec.Supports(tcpState) {
		t.Fatal("expected Supports=false for TCP")
	}
	// UDP different port — should NOT support.
	otherState := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 80), time.Now())
	if dec.Supports(otherState) {
		t.Fatal("expected Supports=false for port 80")
	}
}

func TestDecoderEmitsReadPropertyEvent(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 47808), time.Now())
	raw := []byte{
		0x81, 0x0A, 0x00, 0x0C,
		0x01, 0x00,
		0x00, 0x05, 0x01, 0x0C,
		0xAA, 0xBB,
	}
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "bacnet" {
		t.Fatalf("unexpected proto: %s", ev.Proto)
	}
	if ev.Kind != "request" {
		t.Fatalf("unexpected kind: %s", ev.Kind)
	}
	if ev.Attributes["service"] != "read-property" {
		t.Fatalf("unexpected service: %v", ev.Attributes["service"])
	}
	if ev.Attributes["is_write"] != false {
		t.Fatalf("expected is_write=false")
	}
}

func TestDecoderEmitsDiscoveryEvent(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 47808, 47808), time.Now())
	raw := []byte{
		0x81, 0x0B, 0x00, 0x08,
		0x01, 0x00,
		0x10, 0x08,
	}
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "discovery" {
		t.Fatalf("expected discovery event, got %+v", events)
	}
}

func TestDecoderEmitsResponseEvent(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.2", "10.0.0.1", 47808, 12345), time.Now())
	// Simple-ACK for ReadProperty: type=0x20, invoke-id=0x01, service=12
	raw := []byte{
		0x81, 0x0A, 0x00, 0x09,
		0x01, 0x00,
		0x20, 0x01, 0x0C,
	}
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "response" {
		t.Fatalf("expected response event, got %+v", events)
	}
}

func TestDecoderNilPacket(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 47808), time.Now())
	events, err := dec.OnPacket(state, nil)
	if err != nil || len(events) != 0 {
		t.Fatalf("expected no events for nil packet")
	}
}
