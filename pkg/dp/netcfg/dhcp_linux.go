// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type dhcpLease struct {
	AddrCIDR string
	RouterIP string
}

const (
	dhcpClientPort = 68
	dhcpServerPort = 67

	dhcpOpRequest = 1

	dhcpHtypeEthernet = 1
	dhcpHlenEthernet  = 6

	dhcpMsgDiscover = 1
	dhcpMsgOffer    = 2
	dhcpMsgRequest  = 3
	dhcpMsgDecline  = 4
	dhcpMsgAck      = 5
	dhcpMsgNak      = 6

	dhcpOptMsgType       = 53
	dhcpOptRequestIP     = 50
	dhcpOptServerID      = 54
	dhcpOptParamReqList  = 55
	dhcpOptClientID      = 61
	dhcpOptHostName      = 12
	dhcpOptRouter        = 3
	dhcpOptSubnetMask    = 1
	dhcpOptLeaseTime     = 51
	dhcpOptEnd           = 255
	dhcpOptPad           = 0
	dhcpMagicCookie uint32 = 0x63825363
)

func dhcpAcquireV4(ctx context.Context, dev string, timeoutSeconds int) (*dhcpLease, error) {
	dev = strings.TrimSpace(dev)
	if dev == "" {
		return nil, fmt.Errorf("dhcp: empty device")
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 4
	}

	nic, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, fmt.Errorf("dhcp: interface %q not found: %w", dev, err)
	}
	if len(nic.HardwareAddr) < 6 {
		return nil, fmt.Errorf("dhcp: interface %q has no ethernet MAC", dev)
	}

	xid := make([]byte, 4)
	if _, err := rand.Read(xid); err != nil {
		return nil, fmt.Errorf("dhcp: xid: %w", err)
	}
	xidU32 := binary.BigEndian.Uint32(xid)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("dhcp: socket: %w", err)
	}
	defer unix.Close(fd)

	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)

	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: dhcpClientPort}); err != nil {
		return nil, fmt.Errorf("dhcp: bind :%d: %w", dhcpClientPort, err)
	}

	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	type offer struct {
		yiaddr   net.IP
		serverID net.IP
		router   net.IP
		mask     net.IPMask
	}

	send := func(pkt []byte) error {
		var bcast [4]byte
		copy(bcast[:], net.IPv4bcast.To4())
		return unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Port: dhcpServerPort, Addr: bcast})
	}

	recv := func() ([]byte, error) {
		buf := make([]byte, 1500)
		for {
			wait := time.Until(deadline)
			if dl, ok := ctx.Deadline(); ok {
				if d := time.Until(dl); d < wait {
					wait = d
				}
			}
			if wait <= 0 {
				return nil, context.DeadlineExceeded
			}
			tv := unix.NsecToTimeval(wait.Nanoseconds())
			_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
					return nil, context.DeadlineExceeded
				}
				return nil, err
			}
			if n > 0 {
				return buf[:n], nil
			}
		}
	}

	build := func(msgType byte, requestedIP, serverID net.IP) ([]byte, error) {
		// Minimal BOOTP/DHCP packet.
		p := make([]byte, 240) // 236 + cookie
		p[0] = dhcpOpRequest
		p[1] = dhcpHtypeEthernet
		p[2] = dhcpHlenEthernet
		p[3] = 0 // hops
		binary.BigEndian.PutUint32(p[4:8], xidU32)
		// secs/flags
		p[10] = 0x80 // broadcast flag (0x8000)
		copy(p[28:34], nic.HardwareAddr[:6])
		binary.BigEndian.PutUint32(p[236:240], dhcpMagicCookie)

		opts := make([]byte, 0, 128)
		opts = appendOpt(opts, dhcpOptMsgType, []byte{msgType})
		// Client Identifier: type(ethernet) + mac
		opts = appendOpt(opts, dhcpOptClientID, append([]byte{dhcpHtypeEthernet}, nic.HardwareAddr[:6]...))
		// Hostname (best-effort)
		if hn := strings.TrimSpace(nic.Name); hn != "" {
			opts = appendOpt(opts, dhcpOptHostName, []byte(hn))
		}
		// Request common parameters: subnet mask, router, DNS (6), MTU (26)
		opts = appendOpt(opts, dhcpOptParamReqList, []byte{dhcpOptSubnetMask, dhcpOptRouter, 6, 26})
		if requestedIP != nil && requestedIP.To4() != nil {
			opts = appendOpt(opts, dhcpOptRequestIP, requestedIP.To4())
		}
		if serverID != nil && serverID.To4() != nil {
			opts = appendOpt(opts, dhcpOptServerID, serverID.To4())
		}
		opts = append(opts, dhcpOptEnd)

		return append(p, opts...), nil
	}

	parse := func(pkt []byte) (byte, offer, error) {
		var out offer
		if len(pkt) < 240 {
			return 0, out, fmt.Errorf("dhcp: short packet")
		}
		if pkt[0] != 2 { // BOOTREPLY
			return 0, out, fmt.Errorf("dhcp: not a reply")
		}
		if binary.BigEndian.Uint32(pkt[4:8]) != xidU32 {
			return 0, out, fmt.Errorf("dhcp: xid mismatch")
		}
		if !bytesEq(pkt[28:34], nic.HardwareAddr[:6]) {
			return 0, out, fmt.Errorf("dhcp: chaddr mismatch")
		}
		if binary.BigEndian.Uint32(pkt[236:240]) != dhcpMagicCookie {
			return 0, out, fmt.Errorf("dhcp: missing cookie")
		}
		out.yiaddr = net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
		msgType := byte(0)
		opts := pkt[240:]
		for i := 0; i < len(opts); {
			switch opts[i] {
			case dhcpOptPad:
				i++
				continue
			case dhcpOptEnd:
				i = len(opts)
				continue
			}
			if i+1 >= len(opts) {
				break
			}
			l := int(opts[i+1])
			if i+2+l > len(opts) {
				break
			}
			code := opts[i]
			val := opts[i+2 : i+2+l]
			switch code {
			case dhcpOptMsgType:
				if len(val) == 1 {
					msgType = val[0]
				}
			case dhcpOptServerID:
				if len(val) == 4 {
					out.serverID = net.IPv4(val[0], val[1], val[2], val[3])
				}
			case dhcpOptRouter:
				if len(val) >= 4 {
					out.router = net.IPv4(val[0], val[1], val[2], val[3])
				}
			case dhcpOptSubnetMask:
				if len(val) == 4 {
					out.mask = net.IPv4Mask(val[0], val[1], val[2], val[3])
				}
			}
			i += 2 + l
		}
		if msgType == 0 {
			return 0, out, fmt.Errorf("dhcp: missing message type")
		}
		return msgType, out, nil
	}

	// Discover
	disc, err := build(dhcpMsgDiscover, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := send(disc); err != nil {
		return nil, err
	}

	var off offer
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("dhcp: timeout waiting for offer on %s", dev)
		}
		b, err := recv()
		if err != nil {
			return nil, fmt.Errorf("dhcp: offer recv: %w", err)
		}
		mt, o, err := parse(b)
		if err != nil {
			continue
		}
		if mt == dhcpMsgOffer && o.yiaddr != nil && o.yiaddr.To4() != nil {
			off = o
			break
		}
	}
	if off.serverID == nil || off.serverID.To4() == nil {
		// Not all servers include server id, but most do. We require it for a minimal client.
		return nil, fmt.Errorf("dhcp: offer missing server identifier")
	}
	if off.mask == nil {
		// Default to /24 if missing; best-effort.
		off.mask = net.CIDRMask(24, 32)
	}

	// Request
	req, err := build(dhcpMsgRequest, off.yiaddr, off.serverID)
	if err != nil {
		return nil, err
	}
	if err := send(req); err != nil {
		return nil, err
	}

	var ack offer
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("dhcp: timeout waiting for ack on %s", dev)
		}
		b, err := recv()
		if err != nil {
			return nil, fmt.Errorf("dhcp: ack recv: %w", err)
		}
		mt, o, err := parse(b)
		if err != nil {
			continue
		}
		if mt == dhcpMsgAck {
			ack = o
			break
		}
		if mt == dhcpMsgNak {
			return nil, fmt.Errorf("dhcp: server NAK")
		}
	}

	ip := ack.yiaddr
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("dhcp: invalid yiaddr in ack")
	}
	mask := ack.mask
	if mask == nil {
		mask = off.mask
		if mask == nil {
			mask = net.CIDRMask(24, 32)
		}
	}
	ones, _ := mask.Size()
	lease := &dhcpLease{
		AddrCIDR: fmt.Sprintf("%s/%d", ip.To4().String(), ones),
	}
	if ack.router != nil && ack.router.To4() != nil {
		lease.RouterIP = ack.router.To4().String()
	}
	return lease, nil
}

func appendOpt(b []byte, code byte, val []byte) []byte {
	if len(val) > 255 {
		val = val[:255]
	}
	b = append(b, code, byte(len(val)))
	return append(b, val...)
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
