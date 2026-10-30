// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
)

// The historical public format uses net.IP.String and a single raw direction
// byte, including for nil/malformed IPs and directions outside the two constants.
func publicID(k Key) string {
	return fmt.Sprintf("%s|%s|%d|%d|%03d|", k.SrcIP.String(), k.DstIP.String(),
		k.SrcPort, k.DstPort, k.Proto) + string([]byte{'0' + byte(k.Dir)})
}

func addressCases() []net.IP {
	return []net.IP{
		nil, {}, {1}, {1, 2, 3}, make(net.IP, 17),
		net.IPv4(192, 0, 2, 1).To4(), net.ParseIP("192.0.2.1"),
		net.ParseIP("::ffff:192.0.2.1"), net.ParseIP("2001:db8::1"),
		net.ParseIP("2001:db8:1:2:3:4:5:6"), net.ParseIP("::"), net.ParseIP("::192.0.2.1"),
	}
}

func TestPublicFlowID(t *testing.T) {
	for _, src := range addressCases() {
		for _, dst := range addressCases() {
			for _, port := range []uint16{0, 80, 502, 65535} {
				for _, proto := range []uint8{0, 6, 17, 255} {
					for _, dir := range []Direction{DirForward, DirReverse, 207, 255} {
						k := Key{src, dst, port, 65535 - port, proto, dir}
						if got, want := k.Hash(), publicID(k); got != want {
							t.Fatalf("Hash() = %q, want %q", got, want)
						}
					}
				}
			}
		}
	}
	k := Key{net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.2"), 12345, 502, 6, DirForward}
	if got := k.Hash(); got != "192.0.2.1|198.51.100.2|12345|502|006|0" {
		t.Fatal(got)
	}
}

func TestMapKeyEquality(t *testing.T) {
	var keys []Key
	for _, src := range addressCases() {
		for _, dst := range addressCases() {
			keys = append(keys, Key{SrcIP: src, DstIP: dst, SrcPort: 12345, DstPort: 502, Proto: 6})
		}
	}
	base := keys[len(keys)-1]
	for field := range 4 {
		k := base
		switch field {
		case 0:
			k.SrcPort++
		case 1:
			k.DstPort++
		case 2:
			k.Proto++
		case 3:
			k.Dir++
		}
		keys = append(keys, k)
	}
	for _, a := range keys {
		for _, b := range keys {
			if (a.MapKey() == b.MapKey()) != (publicID(a) == publicID(b)) {
				t.Fatalf("map equality differs for %q and %q", publicID(a), publicID(b))
			}
		}
		for _, dir := range []Direction{DirForward, DirReverse} {
			b := a.Reversed()
			b.Dir = dir
			if a.MapKey().Bidirectional() != b.MapKey().Bidirectional() {
				t.Fatalf("bidirectional key differs for %q and %q", publicID(a), publicID(b))
			}
		}
	}
}

func TestTupleMapKey(t *testing.T) {
	for _, pair := range [][2]string{
		{"192.0.2.1:12345", "198.51.100.2:502"},
		{"[::ffff:192.0.2.1]:12345", "[2001:db8::1]:502"},
		{"[fe80::1%eth0]:12345", "[fe80::2%eth1]:502"},
	} {
		tuple := conntrack.Tuple{Source: netip.MustParseAddrPort(pair[0]),
			Destination: netip.MustParseAddrPort(pair[1]), Protocol: 6}
		for _, dir := range []Direction{DirForward, DirReverse} {
			if TupleMapKey(tuple, dir) != TupleKey(tuple, dir).MapKey() {
				t.Fatalf("tuple key mismatch: %v", tuple)
			}
		}
	}
	if TupleMapKey(conntrack.Tuple{}, DirForward) != TupleKey(conntrack.Tuple{}, DirForward).MapKey() {
		t.Fatal("invalid tuple key mismatch")
	}
}

func TestStateID(t *testing.T) {
	k := Key{net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.2"), 12345, 502, 6, DirForward}
	s := NewState(k, time.Now())
	snapshot := *s
	check := func(s *State) {
		t.Helper()
		if got, want := s.ID(), publicID(s.Key); got != want {
			t.Fatalf("ID() = %q, want %q", got, want)
		}
	}
	check(s)
	check(&snapshot)
	check(&State{Key: k})
	check(&State{})
	s.Key.Dir = DirReverse
	check(s)
	s.Key = s.Key.Reversed()
	check(s)
	s.Key.SrcIP[0] ^= 1 // callers can mutate the address bytes, not just Key
	check(s)
	check(&snapshot)
}

func TestFlowKeyAllocations(t *testing.T) {
	for _, ip := range []string{"192.0.2.1", "2001:db8:1234:5678:abcd:1234:abcd:5678"} {
		k := Key{net.ParseIP(ip), net.ParseIP(ip), 12345, 502, 6, DirForward}
		s := NewState(k, time.Now())
		if n := testing.AllocsPerRun(100, func() { benchmarkID = k.Hash() }); n != 1 {
			t.Fatalf("%s: public Hash allocated %g times, want 1", ip, n)
		}
		if n := testing.AllocsPerRun(100, func() {
			benchmarkID = s.ID()
			benchmarkMapKey = k.MapKey()
		}); n != 0 {
			t.Fatalf("%s: cached ID and MapKey allocated %g times, want 0", ip, n)
		}
	}
}

func FuzzPublicFlowID(f *testing.F) {
	f.Add([]byte{192, 0, 2, 1}, []byte{198, 51, 100, 2}, uint16(12345), uint16(502), uint8(6), uint8(0))
	f.Add([]byte(nil), []byte{1, 2, 3}, uint16(0), uint16(65535), uint8(255), uint8(255))
	f.Fuzz(func(t *testing.T, src, dst []byte, sport, dport uint16, proto, dir uint8) {
		k := Key{src, dst, sport, dport, proto, Direction(dir)}
		if got, want := k.Hash(), publicID(k); got != want {
			t.Fatalf("Hash() = %q, want %q", got, want)
		}
	})
}

var benchmarkID string
var benchmarkMapKey MapKey

func BenchmarkFlowKey(b *testing.B) {
	for _, ip := range []string{"192.0.2.1", "2001:db8:1234:5678:abcd:1234:abcd:5678"} {
		k := Key{net.ParseIP(ip), net.ParseIP(ip), 12345, 502, 6, DirForward}
		s := NewState(k, time.Now())
		b.Run(ip+"/Hash", func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				benchmarkID = k.Hash()
			}
		})
		b.Run(ip+"/ID", func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				benchmarkID = s.ID()
			}
		})
		b.Run(ip+"/MapKey", func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				benchmarkMapKey = k.MapKey()
			}
		})
	}
}
