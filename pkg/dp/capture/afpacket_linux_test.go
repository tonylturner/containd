// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"bytes"
	"golang.org/x/sys/unix"
	"testing"
)

func TestDecodePacketEthernetTCP(t *testing.T) {
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	frame := append(eth, tcpIPv4Packet(7, 0x18, []byte{0x01, 0x02}, 4)...)

	pkt, ok := decodePacket("eth0", frame)
	if !ok {
		t.Fatal("expected successful decode")
	}
	if pkt.Interface != "eth0" || pkt.SrcPort != 40000 || pkt.DstPort != 502 {
		t.Fatalf("unexpected packet: %+v", pkt)
	}
	if !pkt.TCP.Valid || pkt.TCP.Seq != 7 || !bytes.Equal(pkt.Payload, []byte{0x01, 0x02}) {
		t.Fatalf("seq=%d has=%v payload=%x, want seq 7 payload 0102", pkt.TCP.Seq, pkt.TCP.Valid, pkt.Payload)
	}
}

func TestOutgoingPacket(t *testing.T) {
	for _, kind := range []uint8{unix.PACKET_HOST, unix.PACKET_BROADCAST, unix.PACKET_MULTICAST, unix.PACKET_OTHERHOST, unix.PACKET_OUTGOING} {
		if got := outgoingPacket(&unix.SockaddrLinklayer{Pkttype: kind}); got != (kind == unix.PACKET_OUTGOING) {
			t.Fatalf("packet type %d: outgoing=%v", kind, got)
		}
	}
	if outgoingPacket(nil) {
		t.Fatal("missing address treated as outgoing")
	}
}
