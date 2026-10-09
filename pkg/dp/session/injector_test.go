// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package session

import (
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
)

// Golden packets computed independently (RFC 1071 checksums over the IPv4
// header and the TCP pseudo-header + header).
func TestBuildRSTGolden(t *testing.T) {
	cases := []struct {
		name string
		r    Reset
		hex  string
	}{
		{"to server", Reset{Src: netip.MustParseAddrPort("10.60.60.10:40000"), Dst: netip.MustParseAddrPort("10.70.0.5:2404"), Seq: 1001},
			"450000280000000040062a400a3c3c0a0a4600059c400964000003e90000000050040000b5c20000"},
		{"to client", Reset{Src: netip.MustParseAddrPort("10.70.0.5:2404"), Dst: netip.MustParseAddrPort("10.60.60.10:40000"), Seq: 0xfffffffe},
			"450000280000000040062a400a4600050a3c3c0a09649c40fffffffe0000000050040000b9ac0000"},
		{"extremes", Reset{Src: netip.MustParseAddrPort("255.255.255.255:65535"), Dst: netip.MustParseAddrPort("0.0.0.0:1"), Seq: 0},
			"450000280000000040067ad1ffffffff00000000ffff0001000000000000000050040000afe00000"},
		{"ipv4-mapped ipv6", Reset{Src: netip.MustParseAddrPort("[::ffff:10.60.60.10]:40000"), Dst: netip.MustParseAddrPort("[::ffff:10.70.0.5]:2404"), Seq: 1001},
			"450000280000000040062a400a3c3c0a0a4600059c400964000003e90000000050040000b5c20000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt, err := buildRST(tc.r)
			if err != nil {
				t.Fatalf("buildRST: %v", err)
			}
			if got := hex.EncodeToString(pkt); got != tc.hex {
				t.Fatalf("packet\n got %s\nwant %s", got, tc.hex)
			}
			if checksum(pkt[:20], 0) != 0 {
				t.Fatal("IPv4 header checksum does not verify")
			}
			s4, d4 := tc.r.Src.Addr().Unmap().As4(), tc.r.Dst.Addr().Unmap().As4()
			if checksum(pkt[20:], pseudoHeaderSum(s4, d4, 20)) != 0 {
				t.Fatal("TCP checksum does not verify")
			}
		})
	}
}

func TestBuildRSTRejectsUnsupportedTuples(t *testing.T) {
	v4 := netip.MustParseAddrPort("10.0.0.1:2404")
	for name, r := range map[string]Reset{
		"ipv6 source":      {Src: netip.MustParseAddrPort("[2001:db8::1]:2404"), Dst: v4},
		"ipv6 destination": {Src: v4, Dst: netip.MustParseAddrPort("[2001:db8::2]:40000")},
		"zero tuple":       {},
		"source port 0":    {Src: netip.MustParseAddrPort("10.0.0.2:0"), Dst: v4},
		"dest port 0":      {Src: v4, Dst: netip.MustParseAddrPort("10.0.0.2:0")},
	} {
		if pkt, err := buildRST(r); err == nil {
			t.Fatalf("%s: buildRST = %x, want error", name, pkt)
		}
	}
}

func TestFakeRecordsResetsAndErrors(t *testing.T) {
	client := netip.MustParseAddrPort("10.60.60.10:40000")
	server := netip.MustParseAddrPort("10.70.0.5:2404")
	toServer := Reset{Src: client, Dst: server, Seq: 1001}
	toClient := Reset{Src: server, Dst: client, Seq: 5001}

	f := &Fake{}
	var inj Injector = f
	if err := inj.SendRST(toServer); err != nil {
		t.Fatalf("SendRST: %v", err)
	}
	sendErr := errors.New("sendto: no route")
	f.SetError(sendErr)
	if err := inj.SendRST(toClient); !errors.Is(err, sendErr) {
		t.Fatalf("SendRST err = %v, want configured error", err)
	}
	if got := f.Resets(); !reflect.DeepEqual(got, []Reset{toServer, toClient}) {
		t.Fatalf("Resets = %+v", got)
	}
	f.Resets()[0].Seq = 0
	if f.Resets()[0].Seq != 1001 {
		t.Fatal("Resets must return a copy")
	}
	if err := inj.Close(); err != nil || !f.Closed() {
		t.Fatalf("Close = %v closed=%v", err, f.Closed())
	}
	if err := inj.SendRST(toServer); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SendRST after Close = %v, want net.ErrClosed", err)
	}
}

func TestFakeConcurrentUse(t *testing.T) {
	f := &Fake{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(seq uint32) {
			defer wg.Done()
			_ = f.SendRST(Reset{Seq: seq})
			f.SetError(nil)
		}(uint32(i))
	}
	wg.Wait()
	if got := len(f.Resets()); got != 8 {
		t.Fatalf("recorded %d resets, want 8", got)
	}
}
