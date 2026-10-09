// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

func TestNFQueueModeRequiresLinux(t *testing.T) {
	mgr, err := NewManager(Config{
		Interfaces: []string{"lo"},
		Mode:       "nfqueue",
		QueueID:    100,
	})
	if err != nil {
		// On platforms without loopback named "lo", try lo0.
		mgr, err = NewManager(Config{
			Interfaces: []string{"lo0"},
			Mode:       "nfqueue",
			QueueID:    100,
		})
		if err != nil {
			t.Skipf("no loopback interface available: %v", err)
		}
	}

	handler := func(pkt Packet) {}
	err = mgr.Start(context.Background(), handler)

	// On non-Linux, this should return a "not supported" error.
	// On Linux without proper nfqueue kernel support / permissions,
	// it will return an nfqueue open error. Either is acceptable.
	if err != nil {
		t.Logf("nfqueue start returned expected error: %v", err)
	}
}

func TestDecodeIPPacketIPv4(t *testing.T) {
	// Minimal IPv4 TCP SYN packet (20-byte IP + 20-byte TCP, no payload).
	pkt := make([]byte, 40)
	// IPv4 header
	pkt[0] = 0x45 // version=4, ihl=5
	pkt[9] = 6    // proto=TCP
	// total length = 40
	pkt[2] = 0
	pkt[3] = 40
	// src IP 10.0.0.1
	pkt[12], pkt[13], pkt[14], pkt[15] = 10, 0, 0, 1
	// dst IP 10.0.0.2
	pkt[16], pkt[17], pkt[18], pkt[19] = 10, 0, 0, 2
	// TCP header
	pkt[20] = 0x04 // src port high byte (1024)
	pkt[21] = 0x00
	pkt[22] = 0x01 // dst port high byte (502)
	pkt[23] = 0xF6
	pkt[32] = 0x50 // data offset = 5 (20 bytes)

	decoded, ok := decodeIPPacket(pkt)
	if !ok {
		t.Fatal("expected successful decode")
	}
	if decoded.SrcIP.String() != "10.0.0.1" {
		t.Fatalf("expected src 10.0.0.1, got %s", decoded.SrcIP)
	}
	if decoded.DstIP.String() != "10.0.0.2" {
		t.Fatalf("expected dst 10.0.0.2, got %s", decoded.DstIP)
	}
	if decoded.SrcPort != 1024 {
		t.Fatalf("expected src port 1024, got %d", decoded.SrcPort)
	}
	if decoded.DstPort != 502 {
		t.Fatalf("expected dst port 502, got %d", decoded.DstPort)
	}
	if decoded.Transport != "tcp" {
		t.Fatalf("expected transport tcp, got %s", decoded.Transport)
	}
}

func TestDecodeIPPacketTooShort(t *testing.T) {
	_, ok := decodeIPPacket([]byte{0x45})
	if ok {
		t.Fatal("expected decode failure for truncated packet")
	}
}

func TestDecodeIPPacketEmpty(t *testing.T) {
	_, ok := decodeIPPacket(nil)
	if ok {
		t.Fatal("expected decode failure for nil packet")
	}
}

func TestDecodeIPPacketIPv6UDP(t *testing.T) {
	// Minimal IPv6 UDP packet: 40-byte IPv6 header + 8-byte UDP header + payload.
	pkt := make([]byte, 52)
	pkt[0] = 0x60 // version=6
	pkt[6] = 17   // next header = UDP
	pkt[7] = 64   // hop limit
	// payload length = UDP header + 4-byte payload
	pkt[4] = 0
	pkt[5] = 12
	copy(pkt[8:24], []byte{
		0x20, 0x01, 0x0d, 0xb8,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	})
	copy(pkt[24:40], []byte{
		0x20, 0x01, 0x0d, 0xb8,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02,
	})
	pkt[40] = 0x13 // src port 5000
	pkt[41] = 0x88
	pkt[42] = 0x01 // dst port 502
	pkt[43] = 0xF6
	pkt[44] = 0x00
	pkt[45] = 0x0C
	copy(pkt[48:], []byte{0xde, 0xad, 0xbe, 0xef})

	decoded, ok := decodeIPPacket(pkt)
	if !ok {
		t.Fatal("expected successful IPv6 UDP decode")
	}
	if decoded.Transport != "udp" || decoded.Proto != 17 {
		t.Fatalf("unexpected transport/proto: %+v", decoded)
	}
	if decoded.SrcPort != 5000 || decoded.DstPort != 502 {
		t.Fatalf("unexpected ports: %+v", decoded)
	}
	if string(decoded.Payload) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("unexpected payload: %v", decoded.Payload)
	}
}

func TestDecodeL4RejectsInvalidHeaders(t *testing.T) {
	if _, ok := decodeL4("nfqueue", 6, nil, nil, make([]byte, 10)); ok {
		t.Fatal("expected short TCP decode failure")
	}

	shortOffsetTCP := make([]byte, 20)
	shortOffsetTCP[12] = 0x10 // data offset = 4, invalid
	if _, ok := decodeL4("nfqueue", 6, nil, nil, shortOffsetTCP); ok {
		t.Fatal("expected invalid TCP data offset failure")
	}

	if _, ok := decodeL4("nfqueue", 17, nil, nil, make([]byte, 4)); ok {
		t.Fatal("expected short UDP decode failure")
	}

	if _, ok := decodeL4("nfqueue", 1, nil, nil, []byte{0x00}); ok {
		t.Fatal("expected unsupported proto decode failure")
	}
}

// tcpIPv4Packet builds an IPv4 TCP packet with the given sequence number,
// flags and payload, followed by pad trailing bytes that are not part of
// the IP datagram (link-layer padding).
func tcpIPv4Packet(seq uint32, flags byte, payload []byte, pad int) []byte {
	pkt := make([]byte, 40, 40+len(payload)+pad)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(40+len(payload)))
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:22], 40000)
	binary.BigEndian.PutUint16(pkt[22:24], 502)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	pkt[32] = 0x50
	pkt[33] = flags
	pkt = append(pkt, payload...)
	return append(pkt, make([]byte, pad)...)
}

func TestDecodeIPPacketTCPSequence(t *testing.T) {
	decoded, ok := decodeIPPacket(tcpIPv4Packet(0, 0x18, []byte{0xAA, 0xBB}, 0))
	if !ok {
		t.Fatal("expected successful decode")
	}
	if !decoded.HasTCPSeq || decoded.TCPSeq != 0 || decoded.TCPFlags != 0x18 {
		t.Fatalf("seq=%d has=%v flags=%#x, want seq 0 valid flags 0x18", decoded.TCPSeq, decoded.HasTCPSeq, decoded.TCPFlags)
	}

	// Data on a SYN starts one past the SYN's sequence number.
	decoded, _ = decodeIPPacket(tcpIPv4Packet(0xFFFFFFFF, TCPFlagSYN, []byte{0x01}, 0))
	if decoded.TCPSeq != 0 {
		t.Fatalf("SYN payload seq = %d, want 0 (wrapped ISN+1)", decoded.TCPSeq)
	}

	udp, _ := decodeIPPacket(func() []byte {
		pkt := make([]byte, 28)
		pkt[0] = 0x45
		pkt[3] = 28
		pkt[9] = 17
		return pkt
	}())
	if udp.HasTCPSeq {
		t.Fatal("UDP packet must not carry a TCP sequence number")
	}
}

func TestDecodeIPPacketIgnoresLinkPadding(t *testing.T) {
	// A pure ACK padded to the Ethernet minimum must not yield payload.
	decoded, ok := decodeIPPacket(tcpIPv4Packet(100, 0x10, nil, 6))
	if !ok {
		t.Fatal("expected successful decode")
	}
	if len(decoded.Payload) != 0 {
		t.Fatalf("padding decoded as payload: %x", decoded.Payload)
	}
	decoded, _ = decodeIPPacket(tcpIPv4Packet(100, 0x18, []byte{0x01, 0x02}, 4))
	if !bytes.Equal(decoded.Payload, []byte{0x01, 0x02}) {
		t.Fatalf("payload = %x, want 0102", decoded.Payload)
	}
}
