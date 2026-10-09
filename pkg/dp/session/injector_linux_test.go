// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package session

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// requireRaw skips unless the test runs as root (raw sockets need
// CAP_NET_RAW); CONTAIND_KERNEL_TESTS=1 turns the skip into a failure. Run:
//
//	GOOS=linux CGO_ENABLED=0 go test -c -o build/session.test ./pkg/dp/session
//	docker run --rm --user 0 -e CONTAIND_KERNEL_TESTS=1 -v "$PWD/build:/w" \
//	  --entrypoint /w/session.test containd/containd:dev -test.run Kernel -test.v
func requireRaw(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		return
	}
	if os.Getenv("CONTAIND_KERNEL_TESTS") == "1" {
		t.Fatal("CONTAIND_KERNEL_TESTS=1 but the test is not running as root")
	}
	t.Skip("raw socket test needs root")
}

// synSniffer reads incoming TCP headers from a raw IPPROTO_TCP socket to
// learn both initial sequence numbers of a loopback handshake.
type synSniffer struct{ fd int }

func newSynSniffer(t *testing.T) *synSniffer {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("sniffer socket: %v", err)
	}
	tv := unix.NsecToTimeval(int64(200 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatalf("sniffer timeout: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return &synSniffer{fd: fd}
}

// isn waits for the SYN (ack=false) or SYN-ACK (ack=true) from src to dst
// and returns its sequence number.
func (s *synSniffer) isn(t *testing.T, src, dst netip.AddrPort, ack bool) uint32 {
	t.Helper()
	buf := make([]byte, 1500)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			continue
		}
		pkt := buf[:n]
		if n < 20 || pkt[0]>>4 != 4 {
			continue
		}
		ihl := int(pkt[0]&0x0f) * 4
		if n < ihl+20 {
			continue
		}
		tcp := pkt[ihl:]
		gotSrc := netip.AddrPortFrom(netip.AddrFrom4([4]byte(pkt[12:16])), binary.BigEndian.Uint16(tcp[0:2]))
		gotDst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(pkt[16:20])), binary.BigEndian.Uint16(tcp[2:4]))
		flags := tcp[13]
		if gotSrc != src || gotDst != dst || flags&0x02 == 0 || (flags&0x10 != 0) != ack {
			continue
		}
		return binary.BigEndian.Uint32(tcp[4:8])
	}
	t.Fatalf("no SYN (ack=%v) from %s to %s", ack, src, dst)
	return 0
}

func addrPort(t *testing.T, a net.Addr) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		t.Fatalf("parse %s: %v", a, err)
	}
	return ap
}

func expectReset(t *testing.T, name string, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("%s read = %v, want ECONNRESET", name, err)
	}
}

// TestKernelInjectorResetsBothEndpoints resets a real loopback connection:
// one spoofed RST per endpoint, each at the sequence the endpoint expects
// next from its peer.
func TestKernelInjectorResetsBothEndpoints(t *testing.T) {
	requireRaw(t)
	sniff := newSynSniffer(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("accept timed out")
	}
	defer server.Close()

	clientAP, serverAP := addrPort(t, client.LocalAddr()), addrPort(t, client.RemoteAddr())
	clientISN := sniff.isn(t, clientAP, serverAP, false)
	serverISN := sniff.isn(t, serverAP, clientAP, true)

	inj, err := NewInjector()
	if err != nil {
		t.Fatalf("NewInjector: %v", err)
	}
	defer inj.Close()

	if err := inj.SendRST(Reset{Src: serverAP, Dst: clientAP, Seq: serverISN + 1}); err != nil {
		t.Fatalf("SendRST to client: %v", err)
	}
	expectReset(t, "client", client)
	if err := inj.SendRST(Reset{Src: clientAP, Dst: serverAP, Seq: clientISN + 1}); err != nil {
		t.Fatalf("SendRST to server: %v", err)
	}
	expectReset(t, "server", server)

	if err := inj.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := inj.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := inj.SendRST(Reset{Src: serverAP, Dst: clientAP}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SendRST after Close = %v, want net.ErrClosed", err)
	}
}

func TestNewInjectorWithoutPrivilegeFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs only without CAP_NET_RAW")
	}
	inj, err := NewInjector()
	if err == nil {
		_ = inj.Close()
		t.Skip("raw sockets are allowed for this user")
	}
	if errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("NewInjector = %v; linux must report the socket error, not ErrUnsupportedPlatform", err)
	}
}
