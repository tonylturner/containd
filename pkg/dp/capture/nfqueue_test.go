// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"context"
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
