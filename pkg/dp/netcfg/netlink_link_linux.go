// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

func setLinkUp(name string) error {
	nic, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	// Skip if interface is already up (common in Docker where interfaces are externally managed)
	if nic.Flags&net.FlagUp != 0 {
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
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	ifi := unix.IfInfomsg{
		Family: unix.AF_UNSPEC,
		Index:  int32(nic.Index),
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
	}
	_ = binary.Write(&req, binary.LittleEndian, ifi)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

const nlaNested = 0x8000

func ensureBridge(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty bridge name")
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
		addRtAttr(b, unix.IFLA_INFO_KIND, append([]byte("bridge"), 0))
	})

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

func ensureVLAN(name string, parentIndex int, vlanID int) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty vlan name")
	}
	if vlanID < 1 || vlanID > 4094 {
		return fmt.Errorf("invalid vlan id %d", vlanID)
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
	link := make([]byte, 4)
	binary.LittleEndian.PutUint32(link, uint32(parentIndex))
	addRtAttr(&req, unix.IFLA_LINK, link)

	addNestedRtAttr(&req, unix.IFLA_LINKINFO, func(b *bytes.Buffer) {
		addRtAttr(b, unix.IFLA_INFO_KIND, append([]byte("vlan"), 0))
		addNestedRtAttr(b, unix.IFLA_INFO_DATA, func(d *bytes.Buffer) {
			// IFLA_VLAN_ID is 1 in linux/if_link.h.
			v := make([]byte, 2)
			binary.LittleEndian.PutUint16(v, uint16(vlanID))
			addRtAttr(d, 1 /* IFLA_VLAN_ID */, v)
		})
	})

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

func setLinkMaster(member string, masterIndex int) error {
	member = strings.TrimSpace(member)
	if member == "" {
		return fmt.Errorf("empty member name")
	}
	nic, err := net.InterfaceByName(member)
	if err != nil {
		return err
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

	m := make([]byte, 4)
	binary.LittleEndian.PutUint32(m, uint32(masterIndex))
	addRtAttr(&req, unix.IFLA_MASTER, m)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

func addNestedRtAttr(parent *bytes.Buffer, attrType uint16, fn func(*bytes.Buffer)) {
	var child bytes.Buffer
	fn(&child)
	addRtAttr(parent, attrType|nlaNested, child.Bytes())
}
