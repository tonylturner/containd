// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package engineapp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The gate's sockets are transparent: the listeners accept connections
// steered to them for addresses this host does not own, and the upstream
// dialer binds the client's address. The dialer's SO_MARK tells the policy
// which connections are the gate's own.

// gateTransparentControl makes a socket transparent for its family and sets
// its mark when non-zero.
func gateTransparentControl(mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			} else {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}
			if serr == nil && mark != 0 {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// gateTransparentListen listens on address with a transparent socket.
func gateTransparentListen(ctx context.Context, network, address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: gateTransparentControl(0)}
	return lc.Listen(ctx, network, address)
}

// gateTransparentDial connects to server from the client's address local on
// a port the kernel picks, marked with mark.
func gateTransparentDial(ctx context.Context, network string, local netip.Addr, mark uint32, server netip.AddrPort) (*net.TCPConn, error) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: local.AsSlice()}, Control: gateTransparentControl(mark)}
	c, err := d.DialContext(ctx, network, server.String())
	if err != nil {
		return nil, err
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("gate dial %s: %T is not a TCP connection", network, c)
	}
	return tc, nil
}

// gateOriginalDst returns the destination the client connected to before
// any DNAT, from connection tracking.
func gateOriginalDst(c *net.TCPConn) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	v6 := gateAddrPort(c.LocalAddr()).Addr().Is6()
	var result netip.AddrPort
	var serr error
	err = raw.Control(func(fd uintptr) {
		if v6 {
			var sa unix.RawSockaddrInet6
			n := uint32(unsafe.Sizeof(sa))
			if _, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_IPV6, unix.SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&n)), 0); e != 0 {
				serr = e
				return
			}
			result = netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), gateSockaddrPort(sa.Port))
			return
		}
		var sa unix.RawSockaddrInet4
		n := uint32(unsafe.Sizeof(sa))
		if _, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_IP, unix.SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&n)), 0); e != 0 {
			serr = e
			return
		}
		result = netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), gateSockaddrPort(sa.Port))
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	return result, serr
}

// gateSockaddrPort converts a network-order sockaddr port.
func gateSockaddrPort(p uint16) uint16 {
	return p>>8 | (p&0xff)<<8
}

const gateFwmarkAcceptSysctl = "/proc/sys/net/ipv4/tcp_fwmark_accept"

// gateFwmarkAccept reports whether accepted sockets inherit the packet mark
// of their SYN. The gate needs that off: its listeners' sockets would
// otherwise carry the local-delivery mark and policy-route their replies.
func gateFwmarkAccept() (bool, error) {
	data, err := os.ReadFile(gateFwmarkAcceptSysctl)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(string(data)) != "0", nil
}
