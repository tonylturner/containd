// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package flow

import (
	"net"
	"testing"
)

func TestICSServiceDirection(t *testing.T) {
	for _, svc := range []struct {
		proto uint8
		port  uint16
	}{{6, 502}, {6, 20000}, {6, 44818}, {6, 2404}, {17, 2222}} {
		for _, tc := range []struct {
			src, dst uint16
			dir      Direction
			known    bool
		}{
			{41000, svc.port, DirForward, true}, {svc.port, 41000, DirReverse, true},
			{svc.port, svc.port, DirForward, false}, {41000, 41001, DirForward, false},
		} {
			dir, known := ICSServiceDirection(svc.proto, tc.src, tc.dst)
			if dir != tc.dir || known != tc.known {
				t.Errorf("%+v %+v: %v %v", svc, tc, dir, known)
			}
		}
	}
	for _, proto := range []uint8{1, 17} {
		if _, known := ICSServiceDirection(proto, 502, 41000); known {
			t.Errorf("unexpected hint for protocol %d", proto)
		}
	}
}

func TestParseKey(t *testing.T) {
	for _, ips := range [][2]string{{"10.0.0.1", "10.0.0.2"}, {"2001:db8::1", "2001:db8::2"}} {
		for _, dir := range []Direction{DirForward, DirReverse} {
			k := Key{SrcIP: net.ParseIP(ips[0]), DstIP: net.ParseIP(ips[1]), SrcPort: 502, DstPort: 65535, Proto: 6, Dir: dir}
			got, ok := ParseKey(k.Hash())
			if !ok || got.Hash() != k.Hash() {
				t.Fatalf("roundtrip %+v: %+v %v", k, got, ok)
			}
		}
	}
	for _, id := range []string{"", "session-id", "a|b|502|41000|006|1", "10.0.0.1|10.0.0.2|65536|502|006|0", "10.0.0.1|10.0.0.2|502|41000|256|0", "10.0.0.1|10.0.0.2|502|41000|006|2", "10.0.0.1|10.0.0.2|502|41000|6|0", "10.0.0.1|10.0.0.2|bad|502|006|0"} {
		if k, ok := ParseKey(id); ok {
			t.Fatalf("accepted %q: %+v", id, k)
		}
	}
}
