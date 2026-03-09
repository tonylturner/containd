// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func smbFlowState(srcPort, dstPort uint16) *flow.State {
	return flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   6,
	}, time.Now())
}

func TestSMBPorts(t *testing.T) {
	d := NewSMBDecoder()
	tcp, udp := d.Ports()
	if len(udp) != 0 {
		t.Fatalf("expected no UDP ports, got %v", udp)
	}
	want := map[uint16]bool{445: true, 139: true}
	for _, p := range tcp {
		if !want[p] {
			t.Fatalf("unexpected TCP port %d", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Fatalf("missing TCP ports: %v", want)
	}
}

// buildSMBv2Packet constructs a minimal SMBv2 packet with NetBIOS header.
// command is the SMBv2 command code. The SMBv2 header is 64 bytes.
func buildSMBv2Packet(command uint16) []byte {
	// SMBv2 header: 64 bytes
	smb := make([]byte, 64)
	// Magic: 0xFE 'S' 'M' 'B'
	smb[0] = 0xFE
	smb[1] = 'S'
	smb[2] = 'M'
	smb[3] = 'B'
	// StructureSize at offset 4 (2 bytes LE) = 64
	binary.LittleEndian.PutUint16(smb[4:6], 64)
	// Command at offset 12 (2 bytes LE)
	binary.LittleEndian.PutUint16(smb[12:14], command)
	// SessionID at offset 44 (8 bytes LE)
	binary.LittleEndian.PutUint64(smb[44:52], 0x1234)

	// NetBIOS Session Service header: type 0x00 + 3-byte length
	nbLen := len(smb)
	nb := []byte{
		0x00,
		byte(nbLen >> 16),
		byte(nbLen >> 8),
		byte(nbLen),
	}
	return append(nb, smb...)
}

// buildSMBv1Packet constructs a minimal SMBv1 packet with NetBIOS header.
func buildSMBv1Packet(command byte) []byte {
	// SMBv1 header: 32 bytes minimum
	smb := make([]byte, 32)
	// Magic: 0xFF 'S' 'M' 'B'
	smb[0] = 0xFF
	smb[1] = 'S'
	smb[2] = 'M'
	smb[3] = 'B'
	// Command at offset 4
	smb[4] = command

	nbLen := len(smb)
	nb := []byte{
		0x00,
		byte(nbLen >> 16),
		byte(nbLen >> 8),
		byte(nbLen),
	}
	return append(nb, smb...)
}

func TestSMBv2Negotiate(t *testing.T) {
	d := NewSMBDecoder()
	st := smbFlowState(49152, 445)
	pkt := &dpi.ParsedPacket{
		Payload: buildSMBv2Packet(0x0000),
		Proto:   "tcp",
		SrcPort: 49152,
		DstPort: 445,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "smb" {
		t.Errorf("proto=%q, want smb", ev.Proto)
	}
	if ev.Kind != "negotiate" {
		t.Errorf("kind=%q, want negotiate", ev.Kind)
	}
	if v := ev.Attributes["version"]; v != "SMB2" {
		t.Errorf("version=%v, want SMB2", v)
	}
}

func TestSMBv1Detection(t *testing.T) {
	d := NewSMBDecoder()
	st := smbFlowState(49152, 445)
	pkt := &dpi.ParsedPacket{
		Payload: buildSMBv1Packet(0x72), // negotiate
		Proto:   "tcp",
		SrcPort: 49152,
		DstPort: 445,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if v := ev.Attributes["version"]; v != "SMB1" {
		t.Errorf("version=%v, want SMB1", v)
	}
	if ev.Kind != "negotiate" {
		t.Errorf("kind=%q, want negotiate", ev.Kind)
	}
}

func TestSMBv2Write(t *testing.T) {
	d := NewSMBDecoder()
	st := smbFlowState(49152, 445)
	pkt := &dpi.ParsedPacket{
		Payload: buildSMBv2Packet(0x0009),
		Proto:   "tcp",
		SrcPort: 49152,
		DstPort: 445,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Kind != "write" {
		t.Errorf("kind=%q, want write", events[0].Kind)
	}
}

func TestSMBNonSMBTraffic(t *testing.T) {
	d := NewSMBDecoder()
	st := smbFlowState(49152, 445)
	pkt := &dpi.ParsedPacket{
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x09, 0x0A},
		Proto:   "tcp",
		SrcPort: 49152,
		DstPort: 445,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for non-SMB traffic, got %d", len(events))
	}
}

func TestSMBShortPayload(t *testing.T) {
	d := NewSMBDecoder()
	st := smbFlowState(49152, 445)
	pkt := &dpi.ParsedPacket{
		Payload: []byte{0x00, 0x01, 0x02},
		Proto:   "tcp",
		SrcPort: 49152,
		DstPort: 445,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for short payload, got %d", len(events))
	}
}
