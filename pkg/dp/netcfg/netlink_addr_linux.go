// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var nlSeq uint32

func addAddr(ifIndex int, ipnet *net.IPNet) error {
	if ipnet == nil {
		return nil
	}
	ip := ipnet.IP
	if ip == nil {
		return nil
	}
	var family int
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		family = unix.AF_INET
	} else {
		ip = ip.To16()
		family = unix.AF_INET6
		if ip == nil {
			return errors.New("invalid IP")
		}
	}
	prefixLen, _ := ipnet.Mask.Size()

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
		Type:  unix.RTM_NEWADDR,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)

	ifa := unix.IfAddrmsg{
		Family:    uint8(family),
		Prefixlen: uint8(prefixLen),
		Flags:     0,
		Scope:     0,
		Index:     uint32(ifIndex),
	}
	_ = binary.Write(&req, binary.LittleEndian, ifa)

	addRtAttr(&req, unix.IFA_LOCAL, ip)
	addRtAttr(&req, unix.IFA_ADDRESS, ip)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))

	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

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
		switch m.Header.Type {
		case unix.NLMSG_ERROR:
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
		case unix.NLMSG_DONE:
			return nil
		}
	}
	return nil
}

func delAddr(ifIndex int, ipnet *net.IPNet) error {
	if ipnet == nil {
		return nil
	}
	ip := ipnet.IP
	if ip == nil {
		return nil
	}
	var family int
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		family = unix.AF_INET
	} else {
		ip = ip.To16()
		family = unix.AF_INET6
		if ip == nil {
			return errors.New("invalid IP")
		}
	}
	prefixLen, _ := ipnet.Mask.Size()

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
		Type:  unix.RTM_DELADDR,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	ifa := unix.IfAddrmsg{
		Family:    uint8(family),
		Prefixlen: uint8(prefixLen),
		Flags:     0,
		Scope:     0,
		Index:     uint32(ifIndex),
	}
	_ = binary.Write(&req, binary.LittleEndian, ifa)
	addRtAttr(&req, unix.IFA_LOCAL, ip)
	addRtAttr(&req, unix.IFA_ADDRESS, ip)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
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
		if -code == int32(unix.EADDRNOTAVAIL) {
			return nil
		}
		return unix.Errno(-code)
	}
	return nil
}

func listAddrs(ifIndex int, family int) ([]*net.IPNet, error) {
	fd, err := openAddrNetlinkSocket()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	seq := atomic.AddUint32(&nlSeq, 1)
	b := buildGetAddrRequest(seq, family)
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	out := []*net.IPNet{}
	buf := make([]byte, 1<<16)
	for {
		done, err := collectNetlinkAddrs(fd, buf, seq, ifIndex, &out)
		if err != nil {
			return nil, err
		}
		if done {
			return out, nil
		}
	}
}

func openAddrNetlinkSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return 0, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return 0, err
	}
	return fd, nil
}

func buildGetAddrRequest(seq uint32, family int) []byte {
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_GETADDR,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	_ = binary.Write(&req, binary.LittleEndian, unix.IfAddrmsg{Family: uint8(family)})
	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	return b
}

func collectNetlinkAddrs(fd int, buf []byte, seq uint32, ifIndex int, out *[]*net.IPNet) (bool, error) {
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return false, err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return false, err
	}
	for _, m := range msgs {
		done, err := handleNetlinkAddrMessage(m, seq, ifIndex, out)
		if err != nil || done {
			return done, err
		}
	}
	return false, nil
}

func handleNetlinkAddrMessage(msg syscall.NetlinkMessage, seq uint32, ifIndex int, out *[]*net.IPNet) (bool, error) {
	if msg.Header.Seq != seq {
		return false, nil
	}
	switch msg.Header.Type {
	case unix.NLMSG_DONE:
		return true, nil
	case unix.NLMSG_ERROR:
		return false, netlinkMessageError(msg.Data)
	case unix.RTM_NEWADDR:
		if ipnet, ok := parseInterfaceAddrMessage(msg, ifIndex); ok {
			*out = append(*out, ipnet)
		}
	}
	return false, nil
}

func netlinkMessageError(data []byte) error {
	if len(data) < 4 {
		return errors.New("netlink error")
	}
	code := int32(binary.LittleEndian.Uint32(data[:4]))
	if code == 0 {
		return nil
	}
	return unix.Errno(-code)
}

func parseInterfaceAddrMessage(msg syscall.NetlinkMessage, ifIndex int) (*net.IPNet, bool) {
	if len(msg.Data) < unix.SizeofIfAddrmsg {
		return nil, false
	}
	am := (*unix.IfAddrmsg)(unsafe.Pointer(&msg.Data[0]))
	if int(am.Index) != ifIndex {
		return nil, false
	}
	ip, ok := parseInterfaceAddrIP(msg.Data[unix.SizeofIfAddrmsg:])
	if !ok {
		return nil, false
	}
	return interfaceAddrNet(am, ip)
}

func parseInterfaceAddrIP(data []byte) (net.IP, bool) {
	var ip net.IP
	for _, a := range parseNetlinkAttrs(data) {
		switch a.Type {
		case unix.IFA_LOCAL:
			ip = net.IP(append([]byte(nil), a.Value...))
		case unix.IFA_ADDRESS:
			if ip == nil {
				ip = net.IP(append([]byte(nil), a.Value...))
			}
		}
	}
	return ip, ip != nil
}

func interfaceAddrNet(am *unix.IfAddrmsg, ip net.IP) (*net.IPNet, bool) {
	ones := int(am.Prefixlen)
	var bits int
	if am.Family == unix.AF_INET {
		ip = ip.To4()
		bits = 32
	} else {
		ip = ip.To16()
		bits = 128
	}
	if ip == nil {
		return nil, false
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, bits)}, true
}

type netlinkAttr struct {
	Type  uint16
	Value []byte
}

func parseNetlinkAttrs(b []byte) []netlinkAttr {
	attrs := []netlinkAttr{}
	for len(b) >= 4 {
		l := int(binary.LittleEndian.Uint16(b[0:2]))
		t := binary.LittleEndian.Uint16(b[2:4])
		if l < 4 || l > len(b) {
			break
		}
		val := append([]byte(nil), b[4:l]...)
		attrs = append(attrs, netlinkAttr{Type: t, Value: val})
		adv := (l + 3) &^ 3
		if adv > len(b) {
			break
		}
		b = b[adv:]
	}
	return attrs
}

func addRtAttr(b *bytes.Buffer, attrType uint16, data []byte) {
	const hdrLen = 4
	l := hdrLen + len(data)
	aligned := (l + 3) & ^3
	h := unix.RtAttr{Len: uint16(l), Type: attrType}
	_ = binary.Write(b, binary.LittleEndian, h)
	_, _ = b.Write(data)
	for i := l; i < aligned; i++ {
		_ = b.WriteByte(0)
	}
}
