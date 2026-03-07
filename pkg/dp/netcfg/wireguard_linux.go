// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

// Minimal WireGuard configuration via generic netlink ("wireguard" family).
// This intentionally avoids external dependencies (wg/wgctrl) so it can run in restricted build environments.

// WireGuard generic netlink API constants (linux/uapi/linux/wireguard.h).
const (
	wgGenlName    = "wireguard"
	wgGenlVersion = 1

	wgCmdGetDevice = 0
	wgCmdSetDevice = 1
)

const (
	wgDeviceAUnspec            = 0
	wgDeviceAIfindex           = 1
	wgDeviceAIfname            = 2
	wgDeviceAPrivateKey        = 3
	wgDeviceAPublicKey         = 4
	wgDeviceAListenPort        = 5
	wgDeviceAFwmark            = 6
	wgDeviceAPeers             = 7
	wgDeviceAFlags             = 8
	wgDeviceALastHandshakeTime = 9
)

const (
	wgPeerAUnspec              = 0
	wgPeerAPublicKey           = 1
	wgPeerAPresharedKey        = 2
	wgPeerAEndpoint            = 3
	wgPeerAPersistentKeepalive = 4
	wgPeerALastHandshakeTime   = 5
	wgPeerARxBytes             = 6
	wgPeerATxBytes             = 7
	wgPeerAAllowedIPs          = 8
	wgPeerAProtocolVersion     = 9
	wgPeerAFlags               = 10
)

const (
	wgAllowedipAUnspec   = 0
	wgAllowedipAFamily   = 1
	wgAllowedipAIpaddr   = 2
	wgAllowedipACidrMask = 3
)

const (
	wgDeviceFReplacePeers = 1 << 0
)

const (
	wgPeerFRemoveMe          = 1 << 0
	wgPeerFReplaceAllowedIPs = 1 << 1
	wgPeerFUpdateOnly        = 1 << 2
)

// Generic netlink control constants (linux/genetlink.h, linux/netlink.h).
const (
	genlIDCtrl       = 0x10
	ctrlCmdGetFamily = 3
)

const (
	ctrlAttrFamilyID   = 1
	ctrlAttrFamilyName = 2
)

type genlMsgHdr struct {
	Cmd      uint8
	Version  uint8
	Reserved uint16
}

func ApplyWireGuard(ctx context.Context, cfg config.WireGuardConfig) error {
	ifName := strings.TrimSpace(cfg.Interface)
	if ifName == "" {
		ifName = "wg0"
	}
	if !cfg.Enabled {
		// Best-effort: if disabled, remove the interface (this also drops its routes).
		_ = deleteLink(ifName)
		return nil
	}
	if err := ensureWireGuard(ifName); err != nil {
		return err
	}
	if err := setLinkUp(ifName); err != nil {
		return err
	}

	nic, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("wireguard: interface %q not found after ensure: %w", ifName, err)
	}

	if err := wgSetDevice(ctx, nic.Index, cfg); err != nil {
		return err
	}

	// Replace IPv4 addresses on the WireGuard interface (we "own" this interface).
	if addrs, err := listAddrs(nic.Index, unix.AF_INET); err == nil {
		for _, a := range addrs {
			_ = delAddr(nic.Index, a)
		}
	}
	if strings.TrimSpace(cfg.AddressCIDR) != "" {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cfg.AddressCIDR))
		if err != nil || ipnet == nil {
			return fmt.Errorf("wireguard: invalid addressCIDR %q", cfg.AddressCIDR)
		}
		if err := addAddr(nic.Index, ipnet); err != nil {
			return fmt.Errorf("wireguard: add addr %s %s: %w", ifName, ipnet.String(), err)
		}
	}

	// Add routes for peer AllowedIPs (best-effort; duplicates ignored).
	for _, p := range cfg.Peers {
		for _, cidr := range p.AllowedIPs {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			if err := addRouteCIDR(nic.Index, cidr); err != nil {
				return err
			}
		}
	}

	return nil
}

func deleteLink(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty link name")
	}
	nic, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	seq := atomic.AddUint32(&nlSeq, 1)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_DELLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	ifi := unix.IfInfomsg{
		Family: unix.AF_UNSPEC,
		Index:  int32(nic.Index),
	}
	_ = binary.Write(&req, binary.LittleEndian, ifi)
	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

func ensureWireGuard(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty wireguard iface name")
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return nil
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	seq := atomic.AddUint32(&nlSeq, 1)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	ifi := unix.IfInfomsg{Family: unix.AF_UNSPEC}
	_ = binary.Write(&req, binary.LittleEndian, ifi)

	addRtAttr(&req, unix.IFLA_IFNAME, append([]byte(name), 0))
	addNestedRtAttr(&req, unix.IFLA_LINKINFO, func(b *bytes.Buffer) {
		addRtAttr(b, unix.IFLA_INFO_KIND, append([]byte("wireguard"), 0))
	})

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

func addRouteCIDR(ifIndex int, cidr string) error {
	_, dst, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || dst == nil {
		return fmt.Errorf("wireguard: allowedIP route invalid CIDR %q", cidr)
	}
	ip := dst.IP
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	} else {
		// IPv6 routes for AllowedIPs are phased.
		return nil
	}
	prefixLen, _ := dst.Mask.Size()

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	seq := atomic.AddUint32(&nlSeq, 1)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_NEWROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	rtm := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  uint8(prefixLen),
		Src_len:  0,
		Tos:      0,
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Scope:    unix.RT_SCOPE_LINK,
		Type:     unix.RTN_UNICAST,
		Flags:    0,
	}
	_ = binary.Write(&req, binary.LittleEndian, rtm)

	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(ifIndex))
	addRtAttr(&req, unix.RTA_OIF, oif)
	addRtAttr(&req, unix.RTA_DST, ip)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readRouteAck(fd, seq)
}

func readRouteAck(fd int, seq uint32) error {
	buf := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Seq != seq {
			continue
		}
		if m.Header.Type != unix.NLMSG_ERROR {
			continue
		}
		if len(m.Data) < 4 {
			return errors.New("netlink error")
		}
		code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
		if code == 0 {
			return nil
		}
		if -code == int32(unix.EEXIST) {
			return nil
		}
		return unix.Errno(-code)
	}
	return nil
}

func wgSetDevice(ctx context.Context, ifIndex int, cfg config.WireGuardConfig) error {
	for _, peer := range cfg.Peers {
		pk := strings.TrimSpace(peer.PublicKey)
		if pk == "" {
			return fmt.Errorf("wireguard: peer publicKey is required")
		}
		if _, err := decodeKey32(pk); err != nil {
			return fmt.Errorf("wireguard: peer publicKey: %w", err)
		}
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_GENERIC)
	if err != nil {
		return fmt.Errorf("wireguard: netlink generic socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("wireguard: netlink bind: %w", err)
	}

	familyID, err := genlFamilyID(ctx, fd, wgGenlName)
	if err != nil {
		return err
	}

	seq := atomic.AddUint32(&nlSeq, 1)
	var req bytes.Buffer
	nlh := unix.NlMsghdr{
		Type:  uint16(familyID),
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, nlh)
	_ = binary.Write(&req, binary.LittleEndian, genlMsgHdr{Cmd: wgCmdSetDevice, Version: wgGenlVersion})

	ifi := make([]byte, 4)
	binary.LittleEndian.PutUint32(ifi, uint32(ifIndex))
	addNLAttr(&req, wgDeviceAIfindex, ifi)

	// Replace peers as a set (including allowing an empty set to remove peers).
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, wgDeviceFReplacePeers)
	addNLAttr(&req, wgDeviceAFlags, flags)

	if pk := strings.TrimSpace(cfg.PrivateKey); pk != "" {
		b, err := decodeKey32(pk)
		if err != nil {
			return fmt.Errorf("wireguard: privateKey: %w", err)
		}
		addNLAttr(&req, wgDeviceAPrivateKey, b)
	}
	if cfg.ListenPort > 0 {
		lp := make([]byte, 2)
		binary.LittleEndian.PutUint16(lp, uint16(cfg.ListenPort))
		addNLAttr(&req, wgDeviceAListenPort, lp)
	}

	addNestedNLAttr(&req, wgDeviceAPeers, func(peersBuf *bytes.Buffer) {
		for i, peer := range cfg.Peers {
			idx := uint16(i + 1)
			addNestedNLAttr(peersBuf, idx, func(pbuf *bytes.Buffer) {
				pk := strings.TrimSpace(peer.PublicKey)
				b, _ := decodeKey32(pk)
				addNLAttr(pbuf, wgPeerAPublicKey, b)
				// Replace allowed IPs.
				pflags := make([]byte, 4)
				binary.LittleEndian.PutUint32(pflags, wgPeerFReplaceAllowedIPs)
				addNLAttr(pbuf, wgPeerAFlags, pflags)

				if ka := peer.PersistentKeepalive; ka > 0 {
					v := make([]byte, 2)
					binary.LittleEndian.PutUint16(v, uint16(ka))
					addNLAttr(pbuf, wgPeerAPersistentKeepalive, v)
				}
				if ep := strings.TrimSpace(peer.Endpoint); ep != "" {
					raw, err := encodeSockaddr(ep)
					if err == nil {
						addNLAttr(pbuf, wgPeerAEndpoint, raw)
					}
				}
				addNestedNLAttr(pbuf, wgPeerAAllowedIPs, func(aips *bytes.Buffer) {
					for j, cidr := range peer.AllowedIPs {
						cidr = strings.TrimSpace(cidr)
						if cidr == "" {
							continue
						}
						idx2 := uint16(j + 1)
						addNestedNLAttr(aips, idx2, func(ab *bytes.Buffer) {
							family, ipBytes, mask, ok := parseCIDRForWG(cidr)
							if !ok {
								return
							}
							fb := make([]byte, 2)
							binary.LittleEndian.PutUint16(fb, family)
							addNLAttr(ab, wgAllowedipAFamily, fb)
							addNLAttr(ab, wgAllowedipAIpaddr, ipBytes)
							addNLAttr(ab, wgAllowedipACidrMask, []byte{mask})
						})
					}
				})
			})
		}
	})

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("wireguard: send: %w", err)
	}
	return readGenlAck(ctx, fd, seq)
}

func genlFamilyID(ctx context.Context, fd int, name string) (int, error) {
	seq := atomic.AddUint32(&nlSeq, 1)
	var req bytes.Buffer
	nlh := unix.NlMsghdr{
		Type:  genlIDCtrl,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, nlh)
	_ = binary.Write(&req, binary.LittleEndian, genlMsgHdr{Cmd: ctrlCmdGetFamily, Version: 1})
	addNLAttr(&req, ctrlAttrFamilyName, append([]byte(name), 0))

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, err
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		if time.Now().After(deadline) {
			return 0, context.DeadlineExceeded
		}
		buf := make([]byte, 8192)
		tv := unix.NsecToTimeval(time.Until(deadline).Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return 0, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return 0, err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				if len(m.Data) < 4 {
					return 0, errors.New("netlink error")
				}
				code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
				if code == 0 {
					continue
				}
				return 0, unix.Errno(-code)
			}
			// Skip generic netlink header (4 bytes).
			if len(m.Data) < 4 {
				continue
			}
			attrs := m.Data[4:]
			id := parseU16Attr(attrs, ctrlAttrFamilyID)
			if id > 0 {
				return int(id), nil
			}
		}
	}
}

func readGenlAck(ctx context.Context, fd int, seq uint32) error {
	deadline := time.Now().Add(2 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	for {
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		buf := make([]byte, 8192)
		tv := unix.NsecToTimeval(time.Until(deadline).Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			if m.Header.Type != unix.NLMSG_ERROR {
				continue
			}
			if len(m.Data) < 4 {
				return errors.New("netlink error")
			}
			code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
			if code == 0 {
				return nil
			}
			return unix.Errno(-code)
		}
	}
}

func addNLAttr(b *bytes.Buffer, attrType uint16, value []byte) {
	l := 4 + len(value)
	pad := (4 - (l % 4)) % 4
	h := make([]byte, 4)
	binary.LittleEndian.PutUint16(h[0:2], uint16(l))
	binary.LittleEndian.PutUint16(h[2:4], attrType)
	b.Write(h)
	b.Write(value)
	if pad > 0 {
		b.Write(make([]byte, pad))
	}
}

func addNestedNLAttr(b *bytes.Buffer, attrType uint16, fn func(*bytes.Buffer)) {
	var child bytes.Buffer
	fn(&child)
	addNLAttr(b, attrType|nlaNested, child.Bytes())
}

func parseU16Attr(attrs []byte, wantType uint16) uint16 {
	for len(attrs) >= 4 {
		nlaLen := binary.LittleEndian.Uint16(attrs[0:2])
		nlaType := binary.LittleEndian.Uint16(attrs[2:4]) &^ nlaNested
		if nlaLen < 4 || int(nlaLen) > len(attrs) {
			return 0
		}
		val := attrs[4:int(nlaLen)]
		if nlaType == wantType && len(val) >= 2 {
			return binary.LittleEndian.Uint16(val[:2])
		}
		adv := int((nlaLen + 3) &^ 3)
		if adv <= 0 || adv > len(attrs) {
			return 0
		}
		attrs = attrs[adv:]
	}
	return 0
}

func decodeKey32(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Allow raw base64 or "base64:...." style.
	s = strings.TrimPrefix(s, "base64:")
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return b, nil
}

func parseCIDRForWG(cidr string) (family uint16, ip []byte, mask uint8, ok bool) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ipnet == nil || ipnet.IP == nil {
		return 0, nil, 0, false
	}
	ones, _ := ipnet.Mask.Size()
	if ip4 := ipnet.IP.To4(); ip4 != nil {
		return unix.AF_INET, ip4, uint8(ones), true
	}
	// IPv6 allowed IPs are phased.
	return 0, nil, 0, false
}

func encodeSockaddr(endpoint string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		// allow bare host:port without brackets parsing issues
		parts := strings.Split(endpoint, ":")
		if len(parts) != 2 {
			return nil, err
		}
		host, portStr = parts[0], parts[1]
	}
	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		// Best-effort DNS resolution.
		ips, err := net.LookupIP(strings.TrimSpace(host))
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve endpoint %q: %w", host, err)
		}
		ip = ips[0]
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("endpoint must be IPv4 for now: %q", endpoint)
	}

	// sockaddr_in (16 bytes)
	// struct sockaddr_in { sa_family_t sin_family; __be16 sin_port; struct in_addr sin_addr; ... }
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint16(raw[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(raw[2:4], uint16(port))
	copy(raw[4:8], ip4)
	return raw, nil
}
