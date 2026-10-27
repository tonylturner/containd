// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/engine"
)

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c.(*net.TCPConn)
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c.(*net.TCPConn), s
}

func TestGateEntryMatches(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.5:40000")
	effective := netip.MustParseAddrPort("192.0.2.80:80")
	original := netip.MustParseAddrPort("198.51.100.1:18000")
	up := netip.MustParseAddrPort("10.0.0.5:51000")
	e := &gateEntry{client: client, effective: effective, original: original}
	e.setUpstream(nil, up)
	addr := netip.MustParseAddr
	cases := []struct {
		name string
		req  engine.GateCloseRequest
		want bool
	}{
		{"client host", engine.GateCloseRequest{Host: addr("10.0.0.5")}, true},
		{"server host", engine.GateCloseRequest{Host: addr("192.0.2.80")}, true},
		{"original host", engine.GateCloseRequest{Host: addr("198.51.100.1")}, true},
		{"other host", engine.GateCloseRequest{Host: addr("10.0.0.6")}, false},
		{"client leg", engine.GateCloseRequest{Src: addr("10.0.0.5"), Dst: addr("192.0.2.80"), SrcPort: 40000, DstPort: 80}, true},
		{"client leg reply direction", engine.GateCloseRequest{Src: addr("192.0.2.80"), Dst: addr("10.0.0.5"), SrcPort: 80, DstPort: 40000}, true},
		{"client leg before DNAT", engine.GateCloseRequest{Src: addr("10.0.0.5"), Dst: addr("198.51.100.1"), SrcPort: 40000, DstPort: 18000}, true},
		{"client service", engine.GateCloseRequest{Src: addr("10.0.0.5"), Dst: addr("192.0.2.80"), DstPort: 80}, true},
		{"upstream leg", engine.GateCloseRequest{Src: addr("10.0.0.5"), Dst: addr("192.0.2.80"), SrcPort: 51000, DstPort: 80}, true},
		{"wrong client port", engine.GateCloseRequest{Src: addr("10.0.0.5"), Dst: addr("192.0.2.80"), SrcPort: 40001, DstPort: 80}, false},
		{"wrong service port", engine.GateCloseRequest{Src: addr("10.0.0.5"), Dst: addr("192.0.2.80"), DstPort: 81}, false},
		{"other destination", engine.GateCloseRequest{Src: addr("10.0.0.5"), Dst: addr("192.0.2.81")}, false},
	}
	for _, tc := range cases {
		if got := e.matches(tc.req); got != tc.want {
			t.Errorf("%s: matches = %v, want %v", tc.name, got, tc.want)
		}
	}
	e.clearUpstream(nil)
	if e.matches(engine.GateCloseRequest{Src: addr("10.0.0.5"), Dst: addr("192.0.2.80"), SrcPort: 51000}) {
		t.Fatal("cleared upstream leg still matched")
	}
}

func TestGateRegistryCloseMatchingResetsBothLegs(t *testing.T) {
	reg := newGateRegistry()
	clientSide, gateSide := tcpPair(t)
	upSide, serverSide := tcpPair(t)
	e := &gateEntry{client: gateAddrPort(gateSide.RemoteAddr()), effective: netip.MustParseAddrPort("192.0.2.80:80"), conn: gateSide}
	e.setUpstream(upSide, gateAddrPort(upSide.LocalAddr()))
	reg.add(e)
	other := &gateEntry{client: netip.MustParseAddrPort("10.0.0.9:1"), effective: netip.MustParseAddrPort("192.0.2.80:80"), conn: gateSide}
	reg.add(other)
	if n := reg.closeMatching(engine.GateCloseRequest{Host: netip.MustParseAddr("203.0.113.1")}); n != 0 {
		t.Fatalf("closed %d connections for an unknown host", n)
	}
	if n := reg.closeMatching(engine.GateCloseRequest{Src: e.client.Addr(), Dst: netip.MustParseAddr("192.0.2.80"), SrcPort: e.client.Port(), DstPort: 80}); n != 1 {
		t.Fatalf("closed %d connections, want 1", n)
	}
	for name, c := range map[string]*net.TCPConn{"client": clientSide, "server": serverSide} {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatalf("%s leg still open after the reset", name)
		}
	}
	if reg.lookup(e.client) != nil || reg.count() != 1 {
		t.Fatal("reset connection still registered")
	}
	// A wrapper close forgets its own entry but never a newer one under
	// the same key.
	wrapper := &gateConn{TCPConn: gateSide, reg: reg, entry: e}
	replacement := &gateEntry{client: e.client, effective: e.effective, conn: gateSide}
	reg.add(replacement)
	_ = wrapper.Close()
	if got := reg.lookup(e.client); got != replacement {
		t.Fatalf("closing the old wrapper removed the replacement entry: %v", got)
	}
	_ = (&gateConn{TCPConn: gateSide, reg: reg, entry: replacement}).Close()
	if reg.lookup(e.client) != nil {
		t.Fatal("entry not removed on close")
	}
	if reg.count() != 1 {
		t.Fatalf("registry holds %d entries, want the unrelated one", reg.count())
	}
}

func TestGateUpstreamConnCloseClearsCurrentLegOnly(t *testing.T) {
	upA, _ := tcpPair(t)
	upB, _ := tcpPair(t)
	e := &gateEntry{client: netip.MustParseAddrPort("10.0.0.5:40000"), effective: netip.MustParseAddrPort("192.0.2.80:80")}
	e.setUpstream(upA, gateAddrPort(upA.LocalAddr()))
	stale := &gateUpstreamConn{TCPConn: upA, entry: e}
	e.setUpstream(upB, gateAddrPort(upB.LocalAddr()))
	_ = stale.Close()
	if e.upstream != upB {
		t.Fatal("closing the previous upstream cleared the current one")
	}
	_ = (&gateUpstreamConn{TCPConn: upB, entry: e}).Close()
	if e.upstream != nil || e.upstreamAddr.IsValid() {
		t.Fatal("closing the current upstream left it registered")
	}
}

func TestGateAddrPort(t *testing.T) {
	if got := gateAddrPort(&net.TCPAddr{IP: net.ParseIP("::ffff:10.0.0.5"), Port: 80}); got != netip.MustParseAddrPort("10.0.0.5:80") {
		t.Fatalf("mapped address not unmapped: %s", got)
	}
	if got := gateAddrPort(&net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 53}); got.IsValid() {
		t.Fatalf("UDP address accepted: %s", got)
	}
}
