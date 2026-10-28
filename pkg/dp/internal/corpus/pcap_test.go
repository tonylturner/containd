// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// Independent, minimal serialization: the reader never serializes test input.
func wire(proto uint8, seq uint32, flags capture.TCPFlags, payload string, reverse bool) []byte {
	l4 := 20
	if proto == 17 {
		l4 = 8
	}
	b := make([]byte, 14+20+l4+len(payload))
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{192, 0, 2, 2})
	src, dst := uint16(12345), uint16(502)
	if proto == 17 {
		dst = 2222
	}
	if reverse {
		src, dst = dst, src
		copy(ip[12:16], []byte{192, 0, 2, 2})
		copy(ip[16:20], []byte{192, 0, 2, 1})
	}
	tr := ip[20:]
	binary.BigEndian.PutUint16(tr[:2], src)
	binary.BigEndian.PutUint16(tr[2:4], dst)
	if proto == 6 {
		binary.BigEndian.PutUint32(tr[4:8], seq)
		tr[12] = 0x50
		tr[13] = byte(flags)
		binary.BigEndian.PutUint16(tr[14:16], 4096)
	} else {
		binary.BigEndian.PutUint16(tr[4:6], uint16(len(tr)))
	}
	copy(tr[l4:], payload)
	return b
}
func pcap(order binary.ByteOrder, nano bool, records ...[]byte) []byte {
	b := new(bytes.Buffer)
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	for _, v := range []any{magic, uint16(2), uint16(4), uint32(0), uint32(0), uint32(262144), uint32(1)} {
		if err := binary.Write(b, order, v); err != nil {
			panic(err)
		}
	}
	for i, r := range records {
		for _, v := range []uint32{uint32(i + 1), 123, uint32(len(r)), uint32(len(r))} {
			if err := binary.Write(b, order, v); err != nil {
				panic(err)
			}
		}
		b.Write(r)
	}
	return b.Bytes()
}
func readPackets(t *testing.T, records ...[]byte) []Packet {
	t.Helper()
	p, _, err := ReadPCAP(bytes.NewReader(pcap(binary.LittleEndian, false, records...)), "tiny.pcap", ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestReadFormats(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, nano := range []bool{false, true} {
			raw := pcap(order, nano, wire(6, 0, capture.TCPFlagSYN, "xy", false), wire(17, 0, 0, "ab", false))
			packets, skipped, err := ReadPCAP(bytes.NewReader(raw), "tiny.pcap", ReadOptions{})
			if err != nil || len(packets) != 2 || len(skipped) != 0 {
				t.Fatalf("read: %v %d %v", err, len(packets), skipped)
			}
			p := packets[0]
			if !p.Decoded.TCP.Valid || p.Decoded.TCP.Seq != 0 || p.Decoded.TCP.Flags != capture.TCPFlagSYN || string(p.Decoded.Payload) != "xy" || p.Source[0].Frame != 1 || p.Source[0].End != 2 {
				t.Fatalf("lost metadata: %+v", p)
			}
			want := 123000
			if nano {
				want = 123
			}
			if p.Time.Nanosecond() != want {
				t.Fatalf("timestamp %v", p.Time)
			}
			for i := range raw {
				raw[i] = 0
			}
			if p.Wire[14] != 0x45 || string(p.Decoded.Payload) != "xy" {
				t.Fatal("reader aliases input")
			}
		}
	}
}
func TestReadReject(t *testing.T) {
	valid := pcap(binary.LittleEndian, false, wire(6, 5, 0, "ab", false))
	cases := map[string][]byte{"pcapng": {10, 13, 13, 10}, "header": valid[:23], "record": valid[:30], "payload": valid[:len(valid)-1], "empty": valid[:24]}
	mutate := func(name string, fn func([]byte)) { b := append([]byte(nil), valid...); fn(b); cases[name] = b }
	mutate("linktype", func(b []byte) { b[20] = 101 })
	mutate("version", func(b []byte) { b[4] = 3 })
	mutate("snaplen", func(b []byte) { binary.LittleEndian.PutUint32(b[16:20], 1) })
	mutate("truncated", func(b []byte) { b[36]++ })
	mutate("size", func(b []byte) {
		binary.LittleEndian.PutUint32(b[32:36], MaxPacketBytes+1)
		binary.LittleEndian.PutUint32(b[36:40], MaxPacketBytes+1)
	})
	mutate("timestamp", func(b []byte) { binary.LittleEndian.PutUint32(b[28:32], 1000000) })
	mutate("IPv6", func(b []byte) { b[52] = 0x86; b[53] = 0xdd })
	mutate("fragment", func(b []byte) { b[60] = 0x20 })
	mutate("fragment-offset", func(b []byte) { b[61] = 1 })
	mutate("ip-length", func(b []byte) { b[56] = 0xff })
	mutate("ip-version", func(b []byte) { b[54] = 0x65 })
	mutate("tcp-header", func(b []byte) { b[86] = 0xf0 })
	mutate("transport", func(b []byte) { b[63] = 1 })
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ReadPCAP(bytes.NewReader(b), "bad", ReadOptions{}); err == nil {
				t.Fatal("accepted invalid capture")
			}
		})
	}
	badUDP := wire(17, 0, 0, "xy", false)
	badUDP[38]++
	if _, _, err := ReadPCAP(bytes.NewReader(pcap(binary.BigEndian, false, badUDP)), "bad", ReadOptions{}); err == nil {
		t.Fatal("accepted bad UDP length")
	}
}
func TestReadExplicitSkipped(t *testing.T) {
	arp := make([]byte, 42)
	binary.BigEndian.PutUint16(arp[12:14], 0x0806)
	b := pcap(binary.LittleEndian, false, arp, wire(6, 1, 0, "hi", false))
	if _, _, err := ReadPCAP(bytes.NewReader(b), "arp", ReadOptions{}); err == nil {
		t.Fatal("silently ignored ARP")
	}
	p, skip, err := ReadPCAP(bytes.NewReader(b), "arp", ReadOptions{IgnoreEtherTypes: []uint16{0x0806}})
	if err != nil || len(skip) != 1 || skip[0].Frame != 1 || p[0].Source[0].Frame != 2 {
		t.Fatalf("attribution: %v %v %v", err, skip, p)
	}
}
