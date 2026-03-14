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

type dhcpOffer struct {
	yiaddr   net.IP
	serverID net.IP
	router   net.IP
	mask     net.IPMask
}

type dhcpClient struct {
	dev      string
	nic      *net.Interface
	xid      uint32
	fd       int
	deadline time.Time
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

	dhcpOptMsgType             = 53
	dhcpOptRequestIP           = 50
	dhcpOptServerID            = 54
	dhcpOptParamReqList        = 55
	dhcpOptClientID            = 61
	dhcpOptHostName            = 12
	dhcpOptRouter              = 3
	dhcpOptSubnetMask          = 1
	dhcpOptLeaseTime           = 51
	dhcpOptEnd                 = 255
	dhcpOptPad                 = 0
	dhcpMagicCookie     uint32 = 0x63825363
)

func dhcpAcquireV4(ctx context.Context, dev string, timeoutSeconds int) (*dhcpLease, error) {
	dev = strings.TrimSpace(dev)
	if dev == "" {
		return nil, fmt.Errorf("dhcp: empty device")
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 4
	}
	client, err := newDHCPClient(dev, timeoutSeconds)
	if err != nil {
		return nil, err
	}
	defer unix.Close(client.fd)

	if err := client.sendDiscover(); err != nil {
		return nil, err
	}
	offer, err := client.waitForOffer(ctx)
	if err != nil {
		return nil, err
	}
	ack, err := client.requestLease(ctx, offer)
	if err != nil {
		return nil, err
	}
	return buildLease(offer, ack)
}

func newDHCPClient(dev string, timeoutSeconds int) (*dhcpClient, error) {
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
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("dhcp: socket: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: dhcpClientPort}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("dhcp: bind :%d: %w", dhcpClientPort, err)
	}
	return &dhcpClient{
		dev:      dev,
		nic:      nic,
		xid:      binary.BigEndian.Uint32(xid),
		fd:       fd,
		deadline: time.Now().Add(time.Duration(timeoutSeconds) * time.Second),
	}, nil
}

func (c *dhcpClient) sendDiscover() error {
	pkt, err := c.buildPacket(dhcpMsgDiscover, nil, nil)
	if err != nil {
		return err
	}
	return c.send(pkt)
}

func (c *dhcpClient) waitForOffer(ctx context.Context) (dhcpOffer, error) {
	offer, err := c.waitForMessage(ctx, "offer recv", func(msgType byte, offer dhcpOffer) bool {
		return msgType == dhcpMsgOffer && offer.yiaddr != nil && offer.yiaddr.To4() != nil
	})
	if err != nil {
		return dhcpOffer{}, err
	}
	if offer.serverID == nil || offer.serverID.To4() == nil {
		return dhcpOffer{}, fmt.Errorf("dhcp: offer missing server identifier")
	}
	if offer.mask == nil {
		offer.mask = net.CIDRMask(24, 32)
	}
	return offer, nil
}

func (c *dhcpClient) requestLease(ctx context.Context, offer dhcpOffer) (dhcpOffer, error) {
	pkt, err := c.buildPacket(dhcpMsgRequest, offer.yiaddr, offer.serverID)
	if err != nil {
		return dhcpOffer{}, err
	}
	if err := c.send(pkt); err != nil {
		return dhcpOffer{}, err
	}
	return c.waitForMessage(ctx, "ack recv", func(msgType byte, _ dhcpOffer) bool {
		return msgType == dhcpMsgAck || msgType == dhcpMsgNak
	})
}

func (c *dhcpClient) waitForMessage(ctx context.Context, phase string, accept func(byte, dhcpOffer) bool) (dhcpOffer, error) {
	for {
		if time.Now().After(c.deadline) {
			return dhcpOffer{}, fmt.Errorf("dhcp: timeout waiting for %s on %s", strings.Split(phase, " ")[0], c.dev)
		}
		pkt, err := c.recv(ctx)
		if err != nil {
			return dhcpOffer{}, fmt.Errorf("dhcp: %s: %w", phase, err)
		}
		msgType, offer, err := c.parsePacket(pkt)
		if err != nil {
			continue
		}
		if msgType == dhcpMsgNak {
			return dhcpOffer{}, fmt.Errorf("dhcp: server NAK")
		}
		if accept(msgType, offer) {
			return offer, nil
		}
	}
}

func (c *dhcpClient) send(pkt []byte) error {
	var bcast [4]byte
	copy(bcast[:], net.IPv4bcast.To4())
	return unix.Sendto(c.fd, pkt, 0, &unix.SockaddrInet4{Port: dhcpServerPort, Addr: bcast})
}

func (c *dhcpClient) recv(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 1500)
	for {
		wait := time.Until(c.deadline)
		if dl, ok := ctx.Deadline(); ok {
			if d := time.Until(dl); d < wait {
				wait = d
			}
		}
		if wait <= 0 {
			return nil, context.DeadlineExceeded
		}
		tv := unix.NsecToTimeval(wait.Nanoseconds())
		_ = unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
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

func (c *dhcpClient) buildPacket(msgType byte, requestedIP, serverID net.IP) ([]byte, error) {
	p := make([]byte, 240)
	p[0] = dhcpOpRequest
	p[1] = dhcpHtypeEthernet
	p[2] = dhcpHlenEthernet
	binary.BigEndian.PutUint32(p[4:8], c.xid)
	p[10] = 0x80
	copy(p[28:34], c.nic.HardwareAddr[:6])
	binary.BigEndian.PutUint32(p[236:240], dhcpMagicCookie)

	opts := make([]byte, 0, 128)
	opts = appendOpt(opts, dhcpOptMsgType, []byte{msgType})
	opts = appendOpt(opts, dhcpOptClientID, append([]byte{dhcpHtypeEthernet}, c.nic.HardwareAddr[:6]...))
	if hn := strings.TrimSpace(c.nic.Name); hn != "" {
		opts = appendOpt(opts, dhcpOptHostName, []byte(hn))
	}
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

func (c *dhcpClient) parsePacket(pkt []byte) (byte, dhcpOffer, error) {
	var out dhcpOffer
	if len(pkt) < 240 {
		return 0, out, fmt.Errorf("dhcp: short packet")
	}
	if pkt[0] != 2 {
		return 0, out, fmt.Errorf("dhcp: not a reply")
	}
	if binary.BigEndian.Uint32(pkt[4:8]) != c.xid {
		return 0, out, fmt.Errorf("dhcp: xid mismatch")
	}
	if !bytesEq(pkt[28:34], c.nic.HardwareAddr[:6]) {
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
		parseDHCPOption(opts[i], opts[i+2:i+2+l], &msgType, &out)
		i += 2 + l
	}
	if msgType == 0 {
		return 0, out, fmt.Errorf("dhcp: missing message type")
	}
	return msgType, out, nil
}

func parseDHCPOption(code byte, val []byte, msgType *byte, out *dhcpOffer) {
	switch code {
	case dhcpOptMsgType:
		if len(val) == 1 {
			*msgType = val[0]
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
}

func buildLease(offer, ack dhcpOffer) (*dhcpLease, error) {
	ip := ack.yiaddr
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("dhcp: invalid yiaddr in ack")
	}
	mask := ack.mask
	if mask == nil {
		mask = offer.mask
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
