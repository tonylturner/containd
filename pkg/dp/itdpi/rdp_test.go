// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package itdpi

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func rdpFlowState(srcPort, dstPort uint16) *flow.State {
	return flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   6,
	}, time.Now())
}

// buildTPKT wraps X.224 data in a TPKT header.
func buildTPKT(x224 []byte) []byte {
	tpktLen := 4 + len(x224)
	buf := make([]byte, 4)
	buf[0] = 0x03 // version
	buf[1] = 0x00 // reserved
	binary.BigEndian.PutUint16(buf[2:4], uint16(tpktLen))
	return append(buf, x224...)
}

// buildX224CR builds an X.224 Connection Request with optional data.
func buildX224CR(data []byte) []byte {
	// LI(1) + type(1) + dst-ref(2) + src-ref(2) + class(1) = 7 bytes fixed
	li := byte(6 + len(data)) // LI = fixed fields (6) + data length
	buf := []byte{
		li,
		0xE0,       // Connection Request
		0x00, 0x00, // dst-ref
		0x00, 0x00, // src-ref
		0x00, // class options
	}
	return append(buf, data...)
}

// buildX224CC builds an X.224 Connection Confirm with optional data.
func buildX224CC(data []byte) []byte {
	li := byte(6 + len(data))
	buf := []byte{
		li,
		0xC0,       // Connection Confirm
		0x00, 0x00, // dst-ref
		0x00, 0x00, // src-ref
		0x00, // class options
	}
	return append(buf, data...)
}

// buildNegReq builds an RDP Negotiation Request structure.
func buildNegReq(requestedProtocols uint32) []byte {
	buf := make([]byte, 8)
	buf[0] = 0x01 // type: Negotiation Request
	buf[1] = 0x00 // flags
	binary.LittleEndian.PutUint16(buf[2:4], 8) // length
	binary.LittleEndian.PutUint32(buf[4:8], requestedProtocols)
	return buf
}

// buildNegResp builds an RDP Negotiation Response structure.
func buildNegResp(selectedProtocol uint32) []byte {
	buf := make([]byte, 8)
	buf[0] = 0x02 // type: Negotiation Response
	buf[1] = 0x00 // flags
	binary.LittleEndian.PutUint16(buf[2:4], 8) // length
	binary.LittleEndian.PutUint32(buf[4:8], selectedProtocol)
	return buf
}

func TestRDPPorts(t *testing.T) {
	d := NewRDPDecoder()
	tcp, udp := d.Ports()
	if len(udp) != 0 {
		t.Fatalf("expected no UDP ports, got %v", udp)
	}
	if len(tcp) != 1 || tcp[0] != 3389 {
		t.Fatalf("expected TCP [3389], got %v", tcp)
	}
}

func TestRDPConnectionRequest(t *testing.T) {
	d := NewRDPDecoder()
	st := rdpFlowState(50000, 3389)

	cookie := []byte("Cookie: mstshash=testuser\r\n")
	negReq := buildNegReq(0x03) // TLS + CredSSP
	crData := append(cookie, negReq...)
	pkt := &dpi.ParsedPacket{
		Payload: buildTPKT(buildX224CR(crData)),
		Proto:   "tcp",
		SrcPort: 50000,
		DstPort: 3389,
	}

	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "rdp" {
		t.Errorf("proto=%q, want rdp", ev.Proto)
	}
	if ev.Kind != "connection_request" {
		t.Errorf("kind=%q, want connection_request", ev.Kind)
	}
	if ev.Attributes["stage"] != "connection_request" {
		t.Errorf("stage=%v, want connection_request", ev.Attributes["stage"])
	}
	if ev.Attributes["cookie"] != "testuser" {
		t.Errorf("cookie=%v, want testuser", ev.Attributes["cookie"])
	}
	protos, ok := ev.Attributes["requested_protocols"].([]string)
	if !ok {
		t.Fatalf("requested_protocols not []string: %T", ev.Attributes["requested_protocols"])
	}
	if len(protos) != 2 {
		t.Errorf("expected 2 requested protocols, got %v", protos)
	}
}

func TestRDPConnectionRequestNLA(t *testing.T) {
	d := NewRDPDecoder()
	st := rdpFlowState(50000, 3389)

	// CredSSP only (NLA)
	negReq := buildNegReq(0x02)
	pkt := &dpi.ParsedPacket{
		Payload: buildTPKT(buildX224CR(negReq)),
		Proto:   "tcp",
		SrcPort: 50000,
		DstPort: 3389,
	}

	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Attributes["security_level"] != "nla" {
		t.Errorf("security_level=%v, want nla", ev.Attributes["security_level"])
	}
	protos, ok := ev.Attributes["requested_protocols"].([]string)
	if !ok {
		t.Fatalf("requested_protocols not []string: %T", ev.Attributes["requested_protocols"])
	}
	found := false
	for _, p := range protos {
		if p == "nla" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected nla in requested_protocols, got %v", protos)
	}
}

func TestRDPConnectionConfirm(t *testing.T) {
	d := NewRDPDecoder()
	st := rdpFlowState(3389, 50000)

	// Connection Confirm without negotiation response.
	pkt := &dpi.ParsedPacket{
		Payload: buildTPKT(buildX224CC(nil)),
		Proto:   "tcp",
		SrcPort: 3389,
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
	if ev.Kind != "connection_confirm" {
		t.Errorf("kind=%q, want connection_confirm", ev.Kind)
	}
	if ev.Attributes["stage"] != "connection_confirm" {
		t.Errorf("stage=%v, want connection_confirm", ev.Attributes["stage"])
	}
}

func TestRDPWeakSecurity(t *testing.T) {
	d := NewRDPDecoder()
	st := rdpFlowState(3389, 50000)

	// Connection Confirm with Negotiation Response selecting standard RDP (weak).
	negResp := buildNegResp(0x00) // standard RDP
	pkt := &dpi.ParsedPacket{
		Payload: buildTPKT(buildX224CC(negResp)),
		Proto:   "tcp",
		SrcPort: 3389,
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
	if ev.Kind != "negotiation" {
		t.Errorf("kind=%q, want negotiation", ev.Kind)
	}
	if ev.Attributes["security_level"] != "standard_rdp" {
		t.Errorf("security_level=%v, want standard_rdp", ev.Attributes["security_level"])
	}
	if ev.Attributes["selected_protocol"] != "standard_rdp" {
		t.Errorf("selected_protocol=%v, want standard_rdp", ev.Attributes["selected_protocol"])
	}
	concern, ok := ev.Attributes["security_concern"].(string)
	if !ok || concern == "" {
		t.Error("expected security_concern to be set for standard RDP")
	}
}

func TestRDPShortPacket(t *testing.T) {
	d := NewRDPDecoder()
	st := rdpFlowState(50000, 3389)

	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"one_byte", []byte{0x03}},
		{"three_bytes", []byte{0x03, 0x00, 0x00}},
		{"tpkt_too_short", []byte{0x03, 0x00, 0x00, 0x04}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &dpi.ParsedPacket{
				Payload: tt.payload,
				Proto:   "tcp",
				SrcPort: 50000,
				DstPort: 3389,
			}
			events, err := d.OnPacket(st, pkt)
			if err != nil {
				t.Fatalf("OnPacket error: %v", err)
			}
			if len(events) != 0 {
				t.Fatalf("expected 0 events for short packet %q, got %d", tt.name, len(events))
			}
		})
	}
}

func TestRDPNonRDPTraffic(t *testing.T) {
	d := NewRDPDecoder()
	st := rdpFlowState(50000, 3389)

	tests := []struct {
		name    string
		payload []byte
	}{
		{"random_bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}},
		{"http_request", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"wrong_tpkt_version", []byte{0x02, 0x00, 0x00, 0x0A, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &dpi.ParsedPacket{
				Payload: tt.payload,
				Proto:   "tcp",
				SrcPort: 50000,
				DstPort: 3389,
			}
			events, err := d.OnPacket(st, pkt)
			if err != nil {
				t.Fatalf("OnPacket error: %v", err)
			}
			if len(events) != 0 {
				t.Fatalf("expected 0 events for non-RDP traffic %q, got %d", tt.name, len(events))
			}
		})
	}
}
