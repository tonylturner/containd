// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
	"testing"
)

func TestAFPacketPreservesShortHeaderLoss(t *testing.T) {
	for _, size := range []int{20, 22, 24, 32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			raw := tcpIPv4Packet(7, 0x18, []byte{1, 2}, 4)[:size]
			eth := make([]byte, 14)
			eth[12] = 8
			pkt, ok := decodePacket("eth0", append(eth, raw...))
			if !ok || !pkt.CaptureIncomplete || pkt.TCP.Valid || pkt.SrcIP == nil || pkt.PortsValid != (size >= 24) {
				t.Fatalf("trusted truncation discarded before handler: delivered=%v packet=%+v", ok, pkt)
			}
			// NFQUEUE uses the same public IP decoder and unconditionally
			// delivers its result through generation.deliver.
			inline := DecodeIPPacket(raw)
			if inline.CaptureIncomplete != pkt.CaptureIncomplete || inline.PortsValid != pkt.PortsValid || !inline.SrcIP.Equal(pkt.SrcIP) || inline.SrcPort != pkt.SrcPort {
				t.Fatalf("NFQUEUE/AF_PACKET disagree: %+v %+v", inline, pkt)
			}
			delivered := false
			comp := newCompleter(nil, nil)
			defer comp.close()
			g := newGeneration(func(uint32, Verdict, uint32) error { return nil }, comp, nil)
			g.deliver(1, inline, func(p Packet) Decision {
				delivered = p.CaptureIncomplete && p.Invalid != ""
				return Decision{Action: Accept}
			})
			if !delivered {
				t.Fatal("inline generation lost capture incompleteness")
			}
		})
	}
}

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
