// SPDX-License-Identifier: Apache-2.0

//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func identityFixture(family byte, o, r []byte) []byte {
	doc := append([]byte{family, 0, 0, 0}, nlAttr(1|0x8000, o)...)
	doc = append(doc, nlAttr(2|0x8000, r)...)
	for _, typ := range []uint16{3, 7, 12} {
		v := make([]byte, 4)
		binary.BigEndian.PutUint32(v, 123)
		doc = append(doc, nlAttr(typ, v)...)
	}
	start := make([]byte, 8)
	binary.BigEndian.PutUint64(start, 12345678)
	return append(doc, nlAttr(20|0x8000, nlAttr(1, start))...)
}

func TestIdentityCodec(t *testing.T) {
	for _, pair := range [][2]string{{"192.0.2.1", "198.51.100.2"}, {"2001:db8::1", "2001:db8::2"}} {
		family := uint8(2)
		if netip.MustParseAddr(pair[0]).Is6() {
			family = 10
		}
		o := fixtureTuple(pair[0], pair[1], 41000, 502)
		r := fixtureTuple(pair[1], pair[0], 502, 52000)
		doc := identityFixture(family, o, r)
		e, err := decodeIdentity(doc)
		if err != nil || e.Reply.Destination.Port() != 52000 || e.Start != 12345678 {
			t.Fatalf("decode = %+v, %v", e, err)
		}
		for i, observed := range []Tuple{e.Original, e.Reply} {
			if err := e.Validate(observed); err != nil {
				t.Fatal(err)
			}
			encoded, err := encodeIdentityLookup(observed, uint16(i+1))
			if err != nil {
				t.Fatal(err)
			}
			a, err := attributes(encoded[4:])
			if err != nil || len(a[uint16(i+1)]) == 0 || binary.BigEndian.Uint16(a[18]) != 0 || encoded[0] != family {
				t.Fatalf("bad exact selector: %x, %v", encoded, err)
			}
		}
		for _, withZone := range [][]byte{
			append(append([]byte(nil), doc...), nlAttrU16(18, 7)...),
			identityFixture(family, append(o, nlAttrU16(3, 7)...), r),
			identityFixture(family, o, append(r, nlAttrU16(3, 7)...)),
		} {
			z, err := decodeIdentity(withZone)
			if err != nil || !errors.Is(z.Validate(e.Original), ErrUnsupportedZone) {
				t.Fatalf("accepted nonzero zone: %+v, %v", z, err)
			}
		}
		wrong := e.Original
		wrong.Source = netip.AddrPortFrom(wrong.Source.Addr(), 1)
		if e.Validate(wrong) == nil {
			t.Fatal("accepted nonmember tuple")
		}
		for n := 0; n < len(doc)-16; n++ {
			if _, err := decodeIdentity(doc[:n]); err == nil {
				t.Fatalf("accepted truncated mandatory record at %d", n)
			}
		}
		mixed := append([]byte(nil), doc...)
		mixed[0] = 10
		if family == 10 {
			mixed[0] = 2
		}
		if _, err := decodeIdentity(mixed); err == nil {
			t.Fatal("accepted wrong family")
		}
	}
}

func TestIdentityLookupCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewIdentityReader()
	defer c.Close()
	_, err := c.Lookup(ctx, Tuple{Family: 2, Protocol: 6,
		Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("192.0.2.2:502")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup = %v", err)
	}
}
