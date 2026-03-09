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

func ntpFlowState(srcPort, dstPort uint16) *flow.State {
	return flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   17, // UDP
	}, time.Now())
}

// buildNTPPacket constructs a minimal 48-byte NTP packet.
func buildNTPPacket(li, vn, mode, stratum uint8, refID [4]byte) []byte {
	buf := make([]byte, ntpMinLen)
	buf[0] = (li << 6) | (vn << 3) | mode
	buf[1] = stratum
	buf[2] = 6   // poll interval (log2 seconds = 64s)
	buf[3] = 0xE0 // precision (-32, signed)
	// Root Delay: 0.5 seconds = 0x00008000 in 16.16 fixed point
	binary.BigEndian.PutUint32(buf[4:8], 0x00008000)
	// Root Dispersion: 0.25 seconds
	binary.BigEndian.PutUint32(buf[8:12], 0x00004000)
	// Reference ID
	copy(buf[12:16], refID[:])
	// Timestamps left as zeros for simplicity.
	return buf
}

func TestNTPPorts(t *testing.T) {
	d := NewNTPDecoder()
	tcp, udp := d.Ports()
	if len(tcp) != 0 {
		t.Fatalf("expected no TCP ports, got %v", tcp)
	}
	if len(udp) != 1 || udp[0] != 123 {
		t.Fatalf("expected UDP port [123], got %v", udp)
	}
}

func TestNTPClientRequest(t *testing.T) {
	d := NewNTPDecoder()
	st := ntpFlowState(50000, 123)
	pkt := &dpi.ParsedPacket{
		Payload: buildNTPPacket(0, 4, ntpModeClient, 0, [4]byte{}),
		Proto:   "udp",
		SrcPort: 50000,
		DstPort: 123,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "ntp" {
		t.Errorf("proto=%q, want ntp", ev.Proto)
	}
	if ev.Kind != "request" {
		t.Errorf("kind=%q, want request", ev.Kind)
	}
	if v, ok := ev.Attributes["version"].(uint8); !ok || v != 4 {
		t.Errorf("version=%v, want 4", ev.Attributes["version"])
	}
	if m, ok := ev.Attributes["mode"].(uint8); !ok || m != ntpModeClient {
		t.Errorf("mode=%v, want %d", ev.Attributes["mode"], ntpModeClient)
	}
	if mn := ev.Attributes["mode_name"]; mn != "client" {
		t.Errorf("mode_name=%v, want client", mn)
	}
}

func TestNTPServerResponse(t *testing.T) {
	d := NewNTPDecoder()
	st := ntpFlowState(123, 50000)
	refID := [4]byte{'G', 'P', 'S', 0}
	pkt := &dpi.ParsedPacket{
		Payload: buildNTPPacket(0, 4, ntpModeServer, 1, refID),
		Proto:   "udp",
		SrcPort: 123,
		DstPort: 50000,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "response" {
		t.Errorf("kind=%q, want response", ev.Kind)
	}
	if s, ok := ev.Attributes["stratum"].(uint8); !ok || s != 1 {
		t.Errorf("stratum=%v, want 1", ev.Attributes["stratum"])
	}
	if sn := ev.Attributes["stratum_name"]; sn != "primary" {
		t.Errorf("stratum_name=%v, want primary", sn)
	}
	if rid := ev.Attributes["reference_id"]; rid != "GPS" {
		t.Errorf("reference_id=%v, want GPS", rid)
	}
}

func TestNTPBroadcast(t *testing.T) {
	d := NewNTPDecoder()
	st := ntpFlowState(123, 123)
	pkt := &dpi.ParsedPacket{
		Payload: buildNTPPacket(0, 4, ntpModeBroadcast, 2, [4]byte{192, 168, 1, 1}),
		Proto:   "udp",
		SrcPort: 123,
		DstPort: 123,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "broadcast" {
		t.Errorf("kind=%q, want broadcast", ev.Kind)
	}
	// Stratum 2+: reference ID is an IPv4 address.
	if rid := ev.Attributes["reference_id"]; rid != "192.168.1.1" {
		t.Errorf("reference_id=%v, want 192.168.1.1", rid)
	}
}

func TestNTPControlMode(t *testing.T) {
	d := NewNTPDecoder()
	st := ntpFlowState(50000, 123)
	pkt := &dpi.ParsedPacket{
		Payload: buildNTPPacket(0, 4, ntpModeControl, 0, [4]byte{}),
		Proto:   "udp",
		SrcPort: 50000,
		DstPort: 123,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "control" {
		t.Errorf("kind=%q, want control", ev.Kind)
	}
	if d, ok := ev.Attributes["dangerous"].(bool); !ok || !d {
		t.Errorf("expected dangerous=true, got %v", ev.Attributes["dangerous"])
	}
	if r := ev.Attributes["risk"]; r != "NTP control/monlist amplification" {
		t.Errorf("risk=%v, want NTP control/monlist amplification", r)
	}
}

func TestNTPShortPacket(t *testing.T) {
	d := NewNTPDecoder()
	st := ntpFlowState(50000, 123)
	// Only 20 bytes -- less than the 48-byte minimum.
	pkt := &dpi.ParsedPacket{
		Payload: make([]byte, 20),
		Proto:   "udp",
		SrcPort: 50000,
		DstPort: 123,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for short packet, got %d", len(events))
	}
}

func TestNTPNonNTPTraffic(t *testing.T) {
	d := NewNTPDecoder()
	st := ntpFlowState(50000, 123)
	// Random data on port 123 with invalid version (0).
	payload := make([]byte, 48)
	payload[0] = 0x00 // LI=0, VN=0 (invalid), Mode=0 (invalid)
	payload[1] = 0xFF
	for i := 2; i < 48; i++ {
		payload[i] = byte(i * 7) // pseudo-random fill
	}
	pkt := &dpi.ParsedPacket{
		Payload: payload,
		Proto:   "udp",
		SrcPort: 50000,
		DstPort: 123,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for non-NTP traffic, got %d", len(events))
	}
}
