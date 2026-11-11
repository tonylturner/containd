// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"encoding/binary"
	"fmt"
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

func smbReplyFlowState(srcPort, dstPort uint16) *flow.State {
	return flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.2"),
		DstIP:   net.ParseIP("10.0.0.1"),
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

func buildSMB2NegotiateRequest(dialects ...uint16) []byte {
	smb := make([]byte, 100+2*len(dialects))
	copy(smb, []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(smb[4:6], 64)
	binary.LittleEndian.PutUint16(smb[12:14], 0)
	binary.LittleEndian.PutUint16(smb[64:66], 36)
	binary.LittleEndian.PutUint16(smb[66:68], uint16(len(dialects)))
	for i, dialect := range dialects {
		binary.LittleEndian.PutUint16(smb[100+i*2:102+i*2], dialect)
	}
	return addNetBIOSHeader(smb)
}

func buildSMB2NegotiateResponse(dialect uint16) []byte {
	smb := make([]byte, 128)
	copy(smb, []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(smb[4:6], 64)
	binary.LittleEndian.PutUint16(smb[12:14], 0)
	binary.LittleEndian.PutUint32(smb[16:20], 1)
	binary.LittleEndian.PutUint16(smb[64:66], 65)
	binary.LittleEndian.PutUint16(smb[68:70], dialect)
	return addNetBIOSHeader(smb)
}

func buildSMB1NegotiateRequest(dialects ...string) []byte {
	var body []byte
	for _, dialect := range dialects {
		body = append(body, 0x02)
		body = append(body, dialect...)
		body = append(body, 0)
	}
	smb := make([]byte, 35, 35+len(body))
	copy(smb, []byte{0xFF, 'S', 'M', 'B'})
	smb[4] = 0x72
	binary.LittleEndian.PutUint16(smb[33:35], uint16(len(body)))
	smb = append(smb, body...)
	return addNetBIOSHeader(smb)
}

func buildSMB1NegotiateResponse(index uint16) []byte {
	smb := make([]byte, 37)
	copy(smb, []byte{0xFF, 'S', 'M', 'B'})
	smb[4] = 0x72
	smb[9] = 0x80
	smb[32] = 1
	binary.LittleEndian.PutUint16(smb[33:35], index)
	return addNetBIOSHeader(smb)
}

func addNetBIOSHeader(smb []byte) []byte {
	nb := []byte{0, byte(len(smb) >> 16), byte(len(smb) >> 8), byte(len(smb))}
	return append(nb, smb...)
}

func TestSMBv2Negotiate(t *testing.T) {
	d := NewSMBDecoder()
	st := smbFlowState(49152, 445)
	pkt := &dpi.ParsedPacket{
		Payload: buildSMB2NegotiateRequest(0x0202, 0x0210, 0x0300, 0x0311),
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
	if got := ev.Attributes["dialects_offered"]; fmt.Sprint(got) != "[2.0.2 2.1 3.0 3.1.1]" {
		t.Errorf("dialects_offered=%v", got)
	}
	if _, ok := ev.Attributes["dialect"]; ok {
		t.Error("negotiate request must not claim a selected dialect")
	}
}

func TestSMB2SelectedDialect(t *testing.T) {
	d := NewSMBDecoder()
	st := smbReplyFlowState(445, 49152)
	pkt := &dpi.ParsedPacket{
		Payload: buildSMB2NegotiateResponse(0x0311),
		Proto:   "tcp",
		SrcPort: 445,
		DstPort: 49152,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil || len(events) != 1 {
		t.Fatalf("OnPacket = %v, %v; want one event", events, err)
	}
	if got := events[0].Attributes["dialect"]; got != "3.1.1" {
		t.Errorf("dialect=%v, want negotiated 3.1.1", got)
	}
	if got := events[0].Attributes["version"]; got != "SMB2" {
		t.Errorf("version=%v, want SMB2 family hint", got)
	}
}

func TestSMB1NegotiateDialectSelection(t *testing.T) {
	d := NewSMBDecoder()
	request := &dpi.ParsedPacket{
		Payload: buildSMB1NegotiateRequest("NT LM 0.12", "SMB 2.???"),
		Proto:   "tcp",
		SrcPort: 49152,
		DstPort: 445,
	}
	events, err := d.OnPacket(smbFlowState(49152, 445), request)
	if err != nil || len(events) != 1 {
		t.Fatalf("request OnPacket = %v, %v; want one event", events, err)
	}
	if got := events[0].Attributes["dialects_offered"]; fmt.Sprint(got) != "[NT LM 0.12 SMB 2.???]" {
		t.Errorf("dialects_offered=%v", got)
	}

	response := &dpi.ParsedPacket{
		Payload: buildSMB1NegotiateResponse(1),
		Proto:   "tcp",
		SrcPort: 445,
		DstPort: 49152,
	}
	events, err = d.OnPacket(smbReplyFlowState(445, 49152), response)
	if err != nil || len(events) != 1 {
		t.Fatalf("response OnPacket = %v, %v; want one event", events, err)
	}
	if got := events[0].Attributes["dialect"]; got != "SMB 2.???" {
		t.Errorf("dialect=%v, want selected SMB 2.???", got)
	}
}

func TestSMBNegotiateDialectBounds(t *testing.T) {
	dialects := make([]uint16, maxSMBDialects+1)
	for i := range dialects {
		dialects[i] = 0x0202
	}
	if _, ok := parseSMB2Dialects(buildSMB2NegotiateRequest(dialects...)[4:]); ok {
		t.Fatal("accepted more SMB2 dialects than the parser bound")
	}

	names := make([]string, maxSMBDialects+1)
	for i := range names {
		names[i] = "NT LM 0.12"
	}
	if _, ok := parseSMB1Dialects(buildSMB1NegotiateRequest(names...)[4:]); ok {
		t.Fatal("accepted more SMB1 dialects than the parser bound")
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
