// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"encoding/binary"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func tlsFlowState(srcPort, dstPort uint16) *flow.State {
	return flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   6,
	}, time.Now())
}

// buildClientHello constructs a minimal TLS ClientHello with optional SNI and ALPN.
func buildClientHello(sni string, alpnProtos []string) []byte {
	// Build ClientHello body.
	var ch []byte
	// client_version: TLS 1.2 (0x0303)
	ch = binary.BigEndian.AppendUint16(ch, 0x0303)
	// random: 32 bytes of zeros
	ch = append(ch, make([]byte, 32)...)
	// session_id_length: 0
	ch = append(ch, 0x00)
	// cipher_suites: length(2) + 2 suites (4 bytes each entry is 2 bytes)
	ch = binary.BigEndian.AppendUint16(ch, 4)      // 2 cipher suites = 4 bytes
	ch = binary.BigEndian.AppendUint16(ch, 0x1301) // TLS_AES_128_GCM_SHA256
	ch = binary.BigEndian.AppendUint16(ch, 0xC02F) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	// compression_methods: length(1) + null(1)
	ch = append(ch, 0x01, 0x00)

	// Extensions
	var exts []byte

	// SNI extension (type 0x0000)
	if sni != "" {
		var sniExt []byte
		nameBytes := []byte(sni)
		// SNI list: list_length(2) + type(1) + name_length(2) + name
		sniListLen := 1 + 2 + len(nameBytes)
		sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(sniListLen))
		sniExt = append(sniExt, 0x00) // host_name type
		sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(nameBytes)))
		sniExt = append(sniExt, nameBytes...)

		exts = binary.BigEndian.AppendUint16(exts, 0x0000) // extension type: SNI
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(sniExt)))
		exts = append(exts, sniExt...)
	}

	// ALPN extension (type 0x0010)
	if len(alpnProtos) > 0 {
		var alpnList []byte
		for _, proto := range alpnProtos {
			alpnList = append(alpnList, byte(len(proto)))
			alpnList = append(alpnList, proto...)
		}
		var alpnExt []byte
		alpnExt = binary.BigEndian.AppendUint16(alpnExt, uint16(len(alpnList)))
		alpnExt = append(alpnExt, alpnList...)

		exts = binary.BigEndian.AppendUint16(exts, 0x0010) // extension type: ALPN
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(alpnExt)))
		exts = append(exts, alpnExt...)
	}

	// Append extensions length + extensions
	ch = binary.BigEndian.AppendUint16(ch, uint16(len(exts)))
	ch = append(ch, exts...)

	// Wrap in Handshake header: type=0x01 (ClientHello), length(3 bytes)
	var hs []byte
	hs = append(hs, 0x01) // handshake type: ClientHello
	hs = append(hs, byte(len(ch)>>16), byte(len(ch)>>8), byte(len(ch)))
	hs = append(hs, ch...)

	// Wrap in TLS record: type=0x16, version=0x0301, length(2)
	var rec []byte
	rec = append(rec, 0x16)                          // content type: Handshake
	rec = binary.BigEndian.AppendUint16(rec, 0x0301) // TLS 1.0 record version
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)

	return rec
}

func TestTLSPorts(t *testing.T) {
	d := NewTLSDecoder()
	tcp, udp := d.Ports()
	if len(udp) != 0 {
		t.Fatalf("expected no UDP ports, got %v", udp)
	}
	want := map[uint16]bool{443: true, 8443: true, 9443: true, 993: true, 995: true, 465: true}
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

func TestTLSClientHello(t *testing.T) {
	d := NewTLSDecoder()
	st := tlsFlowState(12345, 443)
	pkt := &dpi.ParsedPacket{
		Payload: buildClientHello("example.com", nil),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 443,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "tls" {
		t.Errorf("proto=%q, want tls", ev.Proto)
	}
	if ev.Kind != "client_hello" {
		t.Errorf("kind=%q, want client_hello", ev.Kind)
	}
	if sni := ev.Attributes["sni"]; sni != "example.com" {
		t.Errorf("sni=%v, want example.com", sni)
	}
}

func TestTLSClientHelloWithALPN(t *testing.T) {
	d := NewTLSDecoder()
	st := tlsFlowState(12345, 443)
	pkt := &dpi.ParsedPacket{
		Payload: buildClientHello("secure.example.com", []string{"h2", "http/1.1"}),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 443,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if sni := ev.Attributes["sni"]; sni != "secure.example.com" {
		t.Errorf("sni=%v, want secure.example.com", sni)
	}
	if alpn := ev.Attributes["alpn"]; alpn != "h2,http/1.1" {
		t.Errorf("alpn=%v, want h2,http/1.1", alpn)
	}
}

func TestTLSJA3Hash(t *testing.T) {
	d := NewTLSDecoder()
	st := tlsFlowState(12345, 443)
	pkt := &dpi.ParsedPacket{
		Payload: buildClientHello("example.com", nil),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 443,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	ja3Hash, ok := ev.Attributes["ja3_hash"].(string)
	if !ok || ja3Hash == "" {
		t.Fatal("ja3_hash missing or empty")
	}
	// MD5 hash is 32 hex characters.
	md5Pattern := regexp.MustCompile(`^[a-f0-9]{32}$`)
	if !md5Pattern.MatchString(ja3Hash) {
		t.Errorf("ja3_hash=%q does not look like an MD5 hash", ja3Hash)
	}
}

func TestTLSNonTLSTraffic(t *testing.T) {
	d := NewTLSDecoder()
	st := tlsFlowState(12345, 443)
	pkt := &dpi.ParsedPacket{
		Payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 443,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for non-TLS traffic, got %d", len(events))
	}
}

func TestTLSShortRecord(t *testing.T) {
	d := NewTLSDecoder()
	st := tlsFlowState(12345, 443)
	// Only 3 bytes -- too short for a TLS record.
	pkt := &dpi.ParsedPacket{
		Payload: []byte{0x16, 0x03, 0x01},
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 443,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for short TLS record, got %d", len(events))
	}
}
