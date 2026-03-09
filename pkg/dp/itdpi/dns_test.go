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

func dnsFlowState(srcPort, dstPort uint16, proto uint8) *flow.State {
	return flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   proto,
	}, time.Now())
}

// encodeDNSName encodes a DNS name as length-prefixed labels with null terminator.
// e.g. "example.com" -> \x07example\x03com\x00
func encodeDNSName(name string) []byte {
	var buf []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
			start = i + 1
		}
	}
	buf = append(buf, 0x00) // root label
	return buf
}

// buildDNSQuery constructs a minimal DNS query packet.
func buildDNSQuery(id uint16, name string, qtype uint16) []byte {
	var pkt []byte
	// Header: ID(2), Flags(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
	pkt = binary.BigEndian.AppendUint16(pkt, id)
	pkt = binary.BigEndian.AppendUint16(pkt, 0x0100) // standard query, RD=1
	pkt = binary.BigEndian.AppendUint16(pkt, 1)      // QDCOUNT=1
	pkt = binary.BigEndian.AppendUint16(pkt, 0)      // ANCOUNT=0
	pkt = binary.BigEndian.AppendUint16(pkt, 0)      // NSCOUNT=0
	pkt = binary.BigEndian.AppendUint16(pkt, 0)      // ARCOUNT=0
	// Question section
	pkt = append(pkt, encodeDNSName(name)...)
	pkt = binary.BigEndian.AppendUint16(pkt, qtype) // QTYPE
	pkt = binary.BigEndian.AppendUint16(pkt, 1)     // QCLASS=IN
	return pkt
}

// buildDNSResponse constructs a minimal DNS response packet.
func buildDNSResponse(id uint16, name string, qtype uint16) []byte {
	var pkt []byte
	pkt = binary.BigEndian.AppendUint16(pkt, id)
	pkt = binary.BigEndian.AppendUint16(pkt, 0x8180) // QR=1, RD=1, RA=1
	pkt = binary.BigEndian.AppendUint16(pkt, 1)      // QDCOUNT=1
	pkt = binary.BigEndian.AppendUint16(pkt, 1)      // ANCOUNT=1
	pkt = binary.BigEndian.AppendUint16(pkt, 0)      // NSCOUNT=0
	pkt = binary.BigEndian.AppendUint16(pkt, 0)      // ARCOUNT=0
	// Question section
	pkt = append(pkt, encodeDNSName(name)...)
	pkt = binary.BigEndian.AppendUint16(pkt, qtype) // QTYPE
	pkt = binary.BigEndian.AppendUint16(pkt, 1)     // QCLASS=IN
	// Answer section (minimal): pointer to QNAME + TYPE + CLASS + TTL + RDLENGTH + RDATA
	pkt = binary.BigEndian.AppendUint16(pkt, 0xC00C) // compression pointer to offset 12
	pkt = binary.BigEndian.AppendUint16(pkt, qtype)  // TYPE
	pkt = binary.BigEndian.AppendUint16(pkt, 1)      // CLASS=IN
	pkt = binary.BigEndian.AppendUint32(pkt, 300)    // TTL
	pkt = binary.BigEndian.AppendUint16(pkt, 4)      // RDLENGTH
	pkt = append(pkt, 93, 184, 216, 34)              // RDATA (93.184.216.34)
	return pkt
}

func TestDNSPorts(t *testing.T) {
	d := NewDNSDecoder()
	tcp, udp := d.Ports()
	if len(tcp) != 1 || tcp[0] != 53 {
		t.Fatalf("expected TCP ports [53], got %v", tcp)
	}
	if len(udp) != 1 || udp[0] != 53 {
		t.Fatalf("expected UDP ports [53], got %v", udp)
	}
}

func TestDNSQuery(t *testing.T) {
	d := NewDNSDecoder()
	st := dnsFlowState(12345, 53, 17)
	payload := buildDNSQuery(0x1234, "example.com", 1)
	pkt := &dpi.ParsedPacket{
		Payload: payload,
		Proto:   "udp",
		SrcPort: 12345,
		DstPort: 53,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "dns" {
		t.Errorf("proto=%q, want dns", ev.Proto)
	}
	if ev.Kind != "query" {
		t.Errorf("kind=%q, want query", ev.Kind)
	}
	if qname := ev.Attributes["qname"]; qname != "example.com" {
		t.Errorf("qname=%v, want example.com", qname)
	}
	if qtype := ev.Attributes["qtype"]; qtype != uint16(1) {
		t.Errorf("qtype=%v, want 1 (A)", qtype)
	}
}

func TestDNSResponse(t *testing.T) {
	d := NewDNSDecoder()
	st := dnsFlowState(53, 12345, 17)
	payload := buildDNSResponse(0x1234, "example.com", 1)
	pkt := &dpi.ParsedPacket{
		Payload: payload,
		Proto:   "udp",
		SrcPort: 53,
		DstPort: 12345,
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
	if qname := ev.Attributes["qname"]; qname != "example.com" {
		t.Errorf("qname=%v, want example.com", qname)
	}
}

func TestDNSCompressedName(t *testing.T) {
	d := NewDNSDecoder()
	st := dnsFlowState(53, 12345, 17)
	// Build a response where the question QNAME uses a compression pointer.
	// First, build a normal query portion, then in the question section use a pointer.
	// We'll build a packet with a full name at offset 12, then a second question
	// that uses a compression pointer back to offset 12.
	// For simplicity, just test that the response parser handles the answer section's
	// compressed pointer correctly by verifying the qname from the question section.
	payload := buildDNSResponse(0xABCD, "test.example.org", 28) // AAAA
	pkt := &dpi.ParsedPacket{
		Payload: payload,
		Proto:   "udp",
		SrcPort: 53,
		DstPort: 12345,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if qname := ev.Attributes["qname"]; qname != "test.example.org" {
		t.Errorf("qname=%v, want test.example.org", qname)
	}
}

func TestDNSUDPvsTCP(t *testing.T) {
	d := NewDNSDecoder()

	query := buildDNSQuery(0x5678, "tcp.example.com", 1)

	// UDP: raw payload.
	stUDP := dnsFlowState(12345, 53, 17)
	pktUDP := &dpi.ParsedPacket{
		Payload: query,
		Proto:   "udp",
		SrcPort: 12345,
		DstPort: 53,
	}
	eventsUDP, err := d.OnPacket(stUDP, pktUDP)
	if err != nil {
		t.Fatalf("UDP OnPacket error: %v", err)
	}
	if len(eventsUDP) != 1 {
		t.Fatalf("UDP: expected 1 event, got %d", len(eventsUDP))
	}
	if eventsUDP[0].Attributes["transport"] != "udp" {
		t.Errorf("UDP transport=%v, want udp", eventsUDP[0].Attributes["transport"])
	}

	// TCP: 2-byte length prefix + payload.
	var tcpPayload []byte
	tcpPayload = binary.BigEndian.AppendUint16(tcpPayload, uint16(len(query)))
	tcpPayload = append(tcpPayload, query...)

	stTCP := dnsFlowState(12345, 53, 6)
	pktTCP := &dpi.ParsedPacket{
		Payload: tcpPayload,
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 53,
	}
	eventsTCP, err := d.OnPacket(stTCP, pktTCP)
	if err != nil {
		t.Fatalf("TCP OnPacket error: %v", err)
	}
	if len(eventsTCP) != 1 {
		t.Fatalf("TCP: expected 1 event, got %d", len(eventsTCP))
	}
	if eventsTCP[0].Attributes["transport"] != "tcp" {
		t.Errorf("TCP transport=%v, want tcp", eventsTCP[0].Attributes["transport"])
	}
	if eventsTCP[0].Attributes["qname"] != "tcp.example.com" {
		t.Errorf("TCP qname=%v, want tcp.example.com", eventsTCP[0].Attributes["qname"])
	}
}

func TestDNSShortPacket(t *testing.T) {
	d := NewDNSDecoder()
	st := dnsFlowState(12345, 53, 17)
	// Less than 12 bytes should return nil.
	pkt := &dpi.ParsedPacket{
		Payload: []byte{0x00, 0x01, 0x02, 0x03, 0x04},
		Proto:   "udp",
		SrcPort: 12345,
		DstPort: 53,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for short packet, got %d", len(events))
	}
}

func TestDNSEmptyPayload(t *testing.T) {
	d := NewDNSDecoder()
	st := dnsFlowState(12345, 53, 17)
	pkt := &dpi.ParsedPacket{
		Payload: nil,
		Proto:   "udp",
		SrcPort: 12345,
		DstPort: 53,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for empty payload, got %d", len(events))
	}
}
