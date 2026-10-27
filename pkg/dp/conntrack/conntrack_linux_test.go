// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
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
