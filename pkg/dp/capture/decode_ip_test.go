// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ipv4TCP builds an IPv4 packet with a 20-byte TCP header and payload; the
// IP total length covers exactly the returned bytes.
func ipv4TCP(payload []byte) []byte {
	pkt := make([]byte, 40, 40+len(payload))
	pkt[0] = 0x45
	pkt[9] = 6
	pkt[12], pkt[13], pkt[14], pkt[15] = 10, 0, 0, 1
	pkt[16], pkt[17], pkt[18], pkt[19] = 10, 0, 0, 2
	pkt[20], pkt[21] = 0x04, 0x00                   // src port 1024
	pkt[22], pkt[23] = 0x09, 0x64                   // dst port 2404
	pkt[24], pkt[25], pkt[26], pkt[27] = 0, 0, 0, 0 // seq 0 is a real value
	pkt[28], pkt[29], pkt[30], pkt[31] = 0x01, 0x02, 0x03, 0x04
	pkt[32] = 0x50                          // data offset 5
	pkt[33] = byte(TCPFlagPSH | TCPFlagACK) // flags
	pkt[34], pkt[35] = 0x72, 0x10           // window 29200
	pkt = append(pkt, payload...)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	return pkt
}

func TestDecodeIPPacketIPv4TCPMeta(t *testing.T) {
	raw := ipv4TCP([]byte{0x68, 0x04})
	got := DecodeIPPacket(raw)
	if got.Invalid != "" {
		t.Fatalf("Invalid = %q, want decoded", got.Invalid)
	}
	if got.SrcIP.String() != "10.0.0.1" || got.DstIP.String() != "10.0.0.2" || got.SrcPort != 1024 || got.DstPort != 2404 {
		t.Fatalf("tuple = %s:%d -> %s:%d", got.SrcIP, got.SrcPort, got.DstIP, got.DstPort)
	}
	if got.Transport != "tcp" || got.Proto != 6 {
		t.Fatalf("transport = %q/%d", got.Transport, got.Proto)
	}
	want := TCPMeta{Valid: true, Seq: 0, Ack: 0x01020304, Flags: TCPFlagPSH | TCPFlagACK, Window: 29200}
	if got.TCP != want {
		t.Fatalf("TCP = %+v, want %+v", got.TCP, want)
	}
	if !got.Timestamp.IsZero() || got.Interface != "" {
		t.Fatalf("DecodeIPPacket must leave Timestamp/Interface to the caller: %+v", got)
	}
	raw[40] = 0xff
	if !bytes.Equal(got.Payload, []byte{0x68, 0x04}) {
		t.Fatalf("payload is not an owned copy: %x", got.Payload)
	}
}

func TestDecodeIPPacketIPv6UDP(t *testing.T) {
	pkt := make([]byte, 52)
	pkt[0] = 0x60
	pkt[5] = 12 // payload length
	pkt[6] = 17
	pkt[23] = 1
	pkt[39] = 2
	pkt[40], pkt[41] = 0x13, 0x88 // src port 5000
	pkt[42], pkt[43] = 0x01, 0xf6 // dst port 502
	copy(pkt[48:], []byte{0xde, 0xad, 0xbe, 0xef})

	got, delivered := decodeIP(pkt)
	if !delivered || got.Invalid != "" {
		t.Fatalf("delivered=%v Invalid=%q", delivered, got.Invalid)
	}
	if got.Transport != "udp" || got.SrcPort != 5000 || got.DstPort != 502 || got.TCP.Valid {
		t.Fatalf("unexpected UDP decode: %+v", got)
	}
	if !bytes.Equal(got.Payload, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("payload = %x", got.Payload)
	}
}

// TestDecodeIPDeliveryUnchanged pins which packets reach the observational
// handler: only packets whose transport header decodes, even if marked invalid.
// Packets that cannot be decoded are accepted inside capture with a reason.
func TestDecodeIPDeliveryUnchanged(t *testing.T) {
	withFrag := func(frag uint16, raw []byte) []byte {
		raw[6], raw[7] = byte(frag>>8), byte(frag)
		return raw
	}
	ipv6 := func(next byte) []byte {
		pkt := make([]byte, 60)
		pkt[0] = 0x60
		pkt[5] = 20 // payload length
		pkt[6] = next
		return pkt
	}
	ipv6TCP := append(ipv6(6), 1, 2, 3, 4)
	ipv6TCP[5] = 24    // payload length: TCP header + 4 bytes
	ipv6TCP[52] = 0x50 // data offset 5
	withTotal := func(total uint16, raw []byte) []byte {
		binary.BigEndian.PutUint16(raw[2:4], total)
		return raw
	}
	shortTCP := ipv4TCP(nil)[:30]
	badOffset := ipv4TCP(nil)
	badOffset[32] = 0x40
	shortUDP := ipv4TCP(nil)[:24]
	shortUDP[9] = 17
	icmp := ipv4TCP(nil)
	icmp[9] = 1
	badIHL := ipv4TCP(nil)
	badIHL[0] = 0x44
	longIHL := ipv4TCP(nil)
	longIHL[0] = 0x4f

	cases := []struct {
		name      string
		raw       []byte
		invalid   string
		delivered bool
	}{
		{"empty", nil, InvalidTruncated, false},
		{"one byte", []byte{0x45}, InvalidTruncated, false},
		{"version", []byte{0x50, 0, 0, 0}, InvalidIPVersion, false},
		{"ihl below 20", badIHL, InvalidIPHeader, false},
		{"ihl beyond data", longIHL[:40], InvalidTruncated, false},
		{"tcp short", shortTCP, InvalidTCPHeader, false},
		{"tcp data offset", badOffset, InvalidTCPHeader, false},
		{"udp short", shortUDP, InvalidUDPHeader, false},
		{"icmp", icmp, InvalidProtocol, false},
		{"ipv6 short", ipv6(0)[:39], InvalidTruncated, false},
		{"ipv6 fragment header", ipv6(44), InvalidFragment, false},
		{"ipv6 hop-by-hop", ipv6(0), InvalidIPv6, false},
		{"ipv6 icmpv6", ipv6(58), InvalidProtocol, false},
		{"ipv4 more fragments", withFrag(0x2000, ipv4TCP([]byte{1})), InvalidFragment, true},
		{"ipv4 fragment offset", withFrag(0x0010, ipv4TCP([]byte{1})), InvalidFragment, true},
		{"ipv4 dont fragment", withFrag(0x4000, ipv4TCP([]byte{1})), "", true},
		{"ipv4 fragment with short tcp", withFrag(0x2000, ipv4TCP(nil)[:30]), InvalidTCPHeader, false},
		{"ipv4 capture shorter than total length", ipv4TCP([]byte{1, 2, 3})[:41], InvalidTruncated, true},
		{"ipv4 total length below header", withTotal(19, ipv4TCP([]byte{1})), InvalidIPHeader, true},
		{"ipv4 total length cuts tcp header", withTotal(30, ipv4TCP([]byte{1})), InvalidTCPHeader, false},
		{"ipv4 fragment wins over truncation", withFrag(0x2000, ipv4TCP([]byte{1, 2}))[:41], InvalidFragment, true},
		{"ipv6 capture shorter than payload length", ipv6TCP[:62], InvalidTruncated, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, delivered := decodeIP(tc.raw)
			if got.Invalid != tc.invalid || delivered != tc.delivered {
				t.Fatalf("Invalid=%q delivered=%v, want %q/%v", got.Invalid, delivered, tc.invalid, tc.delivered)
			}
			if pub := DecodeIPPacket(tc.raw); pub.Invalid != tc.invalid {
				t.Fatalf("DecodeIPPacket Invalid=%q, want %q", pub.Invalid, tc.invalid)
			}
		})
	}
}

func TestDecodeIPInvalidTCPKeepsBestEffortTuple(t *testing.T) {
	raw := ipv4TCP(nil)
	raw[32] = 0x40 // data offset 4
	got := DecodeIPPacket(raw)
	if got.Invalid != InvalidTCPHeader || got.TCP.Valid {
		t.Fatalf("Invalid=%q TCP=%+v", got.Invalid, got.TCP)
	}
	if got.SrcPort != 1024 || got.DstPort != 2404 || got.SrcIP.String() != "10.0.0.1" {
		t.Fatalf("best-effort tuple missing: %+v", got)
	}
	if got.Payload != nil {
		t.Fatalf("payload = %x, want nil", got.Payload)
	}
}

// Link-layer padding beyond the IP length is not payload: a pure ACK padded
// to the Ethernet minimum must decode with an empty payload.
func TestDecodeIPPacketIgnoresPaddingBeyondIPLength(t *testing.T) {
	raw := append(ipv4TCP(nil), 0, 0, 0, 0, 0, 0)
	got := DecodeIPPacket(raw)
	if got.Invalid != "" || len(got.Payload) != 0 {
		t.Fatalf("Invalid=%q payload=%x, want decoded with no payload", got.Invalid, got.Payload)
	}
	v6 := make([]byte, 40+20+4)
	v6[0] = 0x60
	v6[5] = 20
	v6[6] = 6
	v6[52] = 0x50
	if got := DecodeIPPacket(v6); got.Invalid != "" || len(got.Payload) != 0 {
		t.Fatalf("IPv6 Invalid=%q payload=%x, want decoded with no payload", got.Invalid, got.Payload)
	}
}

// A truncated copy keeps its best-effort payload so observational sources
// still see it, but it is never reported as decoded.
func TestDecodeIPPacketTruncatedKeepsBestEffortPayload(t *testing.T) {
	got := DecodeIPPacket(ipv4TCP([]byte{1, 2, 3})[:42])
	if got.Invalid != InvalidTruncated || !got.TCP.Valid || !bytes.Equal(got.Payload, []byte{1, 2}) {
		t.Fatalf("Invalid=%q TCP=%+v payload=%x", got.Invalid, got.TCP, got.Payload)
	}
}

func TestIPTruncationSurvivesIncompleteTransportHeader(t *testing.T) {
	v4 := ipv4TCP([]byte{1, 2, 3})[:32]
	v6 := make([]byte, 52)
	v6[0] = 0x60
	v6[5] = 40
	v6[6] = 6
	for _, raw := range [][]byte{v4, v6} {
		got := DecodeIPPacket(raw)
		if got.Invalid != InvalidTCPHeader || !got.CaptureIncomplete || got.TCP.Valid {
			t.Fatalf("known missing IP bytes masked by TCP header: %+v", got)
		}
	}
	// A genuinely malformed but fully captured header is not capture loss.
	binary.BigEndian.PutUint16(v4[2:4], uint16(len(v4)))
	if got := DecodeIPPacket(v4); got.Invalid != InvalidTCPHeader || got.CaptureIncomplete {
		t.Fatalf("complete malformed packet became loss: %+v", got)
	}
}

func TestFragmentTruncationCannotInventPorts(t *testing.T) {
	raw := ipv4TCP([]byte{1, 2, 3})[:32]
	binary.BigEndian.PutUint16(raw[6:8], 0x0010)
	pkt := DecodeIPPacket(raw)
	if !pkt.CaptureIncomplete || pkt.PortsValid || pkt.TCP.Valid || pkt.SrcPort != 0 || pkt.Invalid != InvalidFragment {
		t.Fatal("noninitial fragment payload treated as L4 header", pkt)
	}
}
