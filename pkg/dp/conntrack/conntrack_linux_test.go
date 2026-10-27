// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package conntrack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"testing"
)

func fixtureTuple(src, dst string, sport, dport uint16) []byte {
	s, d := net.ParseIP(src), net.ParseIP(dst)
	st, dt := uint16(3), uint16(4)
	if s.To4() != nil {
		s, d = s.To4(), d.To4()
		st, dt = 1, 2
	}
	ip := append(nlAttr(st, s), nlAttr(dt, d)...)
	p := append(nlAttr(1, []byte{6}), nlAttrU16(2, sport)...)
	p = append(p, nlAttrU16(3, dport)...)
	return append(nlAttr(1|0x8000, ip), nlAttr(2|0x8000, p)...)
}
func TestParseNetlinkEntry(t *testing.T) {
	for _, tc := range []struct{ src, dst, replySrc, replyDst string }{{"192.0.2.1", "198.51.100.1", "10.0.0.1", "203.0.113.1"}, {"2001:db8::1", "2001:db8::2", "2001:db8:1::1", "2001:db8:1::2"}} {
		t.Run(tc.src, func(t *testing.T) {
			data := append([]byte{0, 0, 0, 0}, nlAttr(1|0x8000, fixtureTuple(tc.src, tc.dst, 1234, 443))...)
			data = append(data, nlAttr(2|0x8000, fixtureTuple(tc.replySrc, tc.replyDst, 8443, 5678))...)
			v := make([]byte, 4)
			binary.BigEndian.PutUint32(v, 120)
			data = append(data, nlAttr(7, v)...)
			binary.BigEndian.PutUint32(v, 4)
			data = append(data, nlAttr(3, v)...)
			binary.BigEndian.PutUint32(v, 42)
			data = append(data, nlAttr(8, v)...)
			data = append(data, nlAttr(4|0x8000, nlAttr(1|0x8000, nlAttr(1, []byte{3})))...)
			e, err := parseEntry(data)
			if err != nil {
				t.Fatal(err)
			}
			if e.Proto != "tcp" || e.Src != tc.src || e.Dst != tc.dst || e.Sport != "1234" || e.Dport != "443" || e.ReplySrc != tc.replySrc || e.ReplyDst != tc.replyDst || e.ReplySport != "8443" || e.ReplyDport != "5678" || e.TimeoutSecs != 120 || e.State != "ESTABLISHED" || !e.Assured || e.Mark != "42" {
				t.Fatalf("entry: %+v", e)
			}
			for n := 0; n < len(data); n++ {
				if _, err := parseEntry(data[:n]); err == nil && n < 4 {
					t.Fatalf("accepted short entry %d", n)
				}
			}
		})
	}
}

// TestICMPTupleRoundTrip encodes each ICMP delete tuple, checks the kernel
// attribute numbers, and parses it back as a listed entry would be.
func TestICMPTupleRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		req           DeleteRequest
		num           byte
		id, typ, code uint16
	}{
		{DeleteRequest{Proto: "icmp", Src: "192.0.2.1", Dst: "198.51.100.1", ICMPID: 4660, ICMPType: 8}, 1, 4, 5, 6},
		{DeleteRequest{Proto: "icmpv6", Src: "2001:db8::1", Dst: "2001:db8::2", ICMPID: 65535, ICMPType: 139, ICMPCode: 1}, 58, 7, 8, 9},
	} {
		t.Run(tc.req.Proto, func(t *testing.T) {
			_, encoded, err := encodeTuple(tc.req)
			if err != nil {
				t.Fatal(err)
			}
			a, err := attributes(encoded)
			if err != nil {
				t.Fatal(err)
			}
			p, err := attributes(a[2])
			if err != nil {
				t.Fatal(err)
			}
			if len(p) != 4 || !bytes.Equal(p[1], []byte{tc.num}) || binary.BigEndian.Uint16(p[tc.id]) != uint16(tc.req.ICMPID) || !bytes.Equal(p[tc.typ], []byte{byte(tc.req.ICMPType)}) || !bytes.Equal(p[tc.code], []byte{byte(tc.req.ICMPCode)}) {
				t.Fatalf("proto attributes %v", p)
			}
			got, err := parseTuple(encoded)
			if err != nil {
				t.Fatal(err)
			}
			want := tuple{proto: tc.req.Proto, src: tc.req.Src, dst: tc.req.Dst, icmpID: strconv.Itoa(tc.req.ICMPID), icmpType: strconv.Itoa(tc.req.ICMPType), icmpCode: strconv.Itoa(tc.req.ICMPCode)}
			if got != want {
				t.Fatalf("parsed %+v, want %+v", got, want)
			}
			// A listed entry needs every ICMP attribute.
			for _, drop := range []uint16{tc.id, tc.typ, tc.code} {
				trimmed := nlAttr(1, []byte{tc.num})
				for _, typ := range []uint16{tc.id, tc.typ, tc.code} {
					if typ != drop {
						trimmed = append(trimmed, nlAttr(typ, p[typ])...)
					}
				}
				if _, err := parseTuple(append(nlAttr(1|0x8000, a[1]), nlAttr(2|0x8000, trimmed)...)); err == nil {
					t.Fatalf("accepted a tuple without attribute %d", drop)
				}
			}
		})
	}
	for _, bad := range []DeleteRequest{
		{Proto: "icmp", Src: "192.0.2.1", Dst: "192.0.2.2", ICMPID: 65536, ICMPType: 8},
		{Proto: "icmp", Src: "192.0.2.1", Dst: "192.0.2.2", ICMPType: 256},
		{Proto: "icmpv6", Src: "2001:db8::1", Dst: "2001:db8::2", ICMPType: 128, ICMPCode: -1},
		{Proto: "sctp", Src: "192.0.2.1", Dst: "192.0.2.2"},
	} {
		if _, _, err := encodeTuple(bad); err == nil {
			t.Fatalf("encoded %+v", bad)
		}
	}
}

func TestParseICMPEntry(t *testing.T) {
	icmp := func(src, dst string, id uint16, typ byte) []byte {
		ip := append(nlAttr(1, net.ParseIP(src).To4()), nlAttr(2, net.ParseIP(dst).To4())...)
		p := append(nlAttr(1, []byte{1}), nlAttrU16(4, id)...)
		p = append(p, nlAttr(5, []byte{typ})...)
		p = append(p, nlAttr(6, []byte{0})...)
		return append(nlAttr(1|0x8000, ip), nlAttr(2|0x8000, p)...)
	}
	// Masquerade can rewrite the identifier of the reply tuple.
	data := append([]byte{0, 0, 0, 0}, nlAttr(1|0x8000, icmp("192.0.2.1", "198.51.100.1", 4660, 8))...)
	data = append(data, nlAttr(2|0x8000, icmp("198.51.100.1", "203.0.113.1", 1, 0))...)
	e, err := parseEntry(data)
	if err != nil {
		t.Fatal(err)
	}
	want := Entry{Proto: "icmp", Src: "192.0.2.1", Dst: "198.51.100.1", ICMPID: "4660", ICMPType: "8", ICMPCode: "0", ReplySrc: "198.51.100.1", ReplyDst: "203.0.113.1", ReplyICMPID: "1", ReplyICMPType: "0", ReplyICMPCode: "0"}
	if e != want {
		t.Fatalf("entry %+v", e)
	}
	if original, err := e.Original(); err != nil || original != (DeleteRequest{Proto: "icmp", Src: e.Src, Dst: e.Dst, ICMPID: 4660, ICMPType: 8}) {
		t.Fatalf("original %+v %v", original, err)
	}
}

func TestMalformedAttributes(t *testing.T) {
	for _, data := range [][]byte{{1}, {3, 0, 1, 0}, {9, 0, 1, 0, 0, 0, 0, 0}} {
		if _, err := attributes(data); err == nil {
			t.Fatalf("accepted %v", data)
		}
	}
	if _, err := parseEntry([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("accepted missing tuples")
	}
}

func TestDeleteCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Delete(ctx, DeleteRequest{Proto: "tcp", Src: "192.0.2.1", Dst: "192.0.2.2", Sport: 1234, Dport: 443})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled delete: %v", err)
	}
}
