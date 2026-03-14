// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

// Minimal fib_rule_hdr from <linux/fib_rules.h>.
type fibRuleHdr struct {
	Family uint8
	DstLen uint8
	SrcLen uint8
	Tos    uint8
	Table  uint8
	Res1   uint8
	Res2   uint8
	Action uint8
	Flags  uint32
}

const (
	// <linux/fib_rules.h>
	frActToTbl = 1

	// <linux/fib_rules.h> FRA_* attributes (subset).
	fraPriority = 6
	fraTable    = 15
	fraSrc      = 2
	fraDst      = 1
)

var nlRuleSeq uint32

func addRule(r config.PolicyRule, idx int) error {
	if r.Table <= 0 || r.Table > 252 {
		return fmt.Errorf("rule table out of range: %d", r.Table)
	}
	priority := r.Priority
	if priority == 0 {
		priority = managedRulePriorityBase + idx
	}

	var srcIP, dstIP net.IP
	var srcLen, dstLen int
	if strings.TrimSpace(r.Src) != "" {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(r.Src))
		if err != nil || ipnet == nil || ipnet.IP == nil {
			return fmt.Errorf("rule src invalid %q", r.Src)
		}
		srcIP = ipnet.IP.To4()
		if srcIP == nil {
			return fmt.Errorf("rule src must be IPv4 for now: %q", r.Src)
		}
		srcLen, _ = ipnet.Mask.Size()
	}
	if strings.TrimSpace(r.Dst) != "" {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(r.Dst))
		if err != nil || ipnet == nil || ipnet.IP == nil {
			return fmt.Errorf("rule dst invalid %q", r.Dst)
		}
		dstIP = ipnet.IP.To4()
		if dstIP == nil {
			return fmt.Errorf("rule dst must be IPv4 for now: %q", r.Dst)
		}
		dstLen, _ = ipnet.Mask.Size()
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	seq := atomic.AddUint32(&nlRuleSeq, 1)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_NEWRULE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	fr := fibRuleHdr{
		Family: unix.AF_INET,
		DstLen: uint8(dstLen),
		SrcLen: uint8(srcLen),
		Table:  uint8(r.Table),
		Action: frActToTbl,
	}
	_ = binary.Write(&req, binary.LittleEndian, fr)

	prio := make([]byte, 4)
	binary.LittleEndian.PutUint32(prio, uint32(priority))
	addRtAttr(&req, fraPriority, prio)

	tbl := make([]byte, 4)
	binary.LittleEndian.PutUint32(tbl, uint32(r.Table))
	addRtAttr(&req, fraTable, tbl)

	if srcIP != nil {
		addRtAttr(&req, fraSrc, srcIP)
	}
	if dstIP != nil {
		addRtAttr(&req, fraDst, dstIP)
	}

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

type kernelRule struct {
	priority uint32
	table    uint32
	src      net.IP
	srcLen   int
	dst      net.IP
	dstLen   int
}

func deleteManagedRules(ctx context.Context) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	seq := atomic.AddUint32(&nlRuleSeq, 1)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_GETRULE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	fr := fibRuleHdr{Family: unix.AF_INET}
	_ = binary.Write(&req, binary.LittleEndian, fr)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	managed, err := listManagedRules(ctx, fd, seq)
	if err != nil {
		return err
	}
	for _, r := range managed {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := delRule(r); err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
				continue
			}
			return err
		}
	}
	return nil
}

func listManagedRules(ctx context.Context, fd int, seq uint32) ([]kernelRule, error) {
	var managed []kernelRule
	buf := make([]byte, 1<<16)
	hdrSize := int(unsafe.Sizeof(fibRuleHdr{}))
	for {
		msgs, err := recvRouteMessages(ctx, fd, buf)
		if err != nil {
			return nil, err
		}
		done, rules, err := extractManagedRules(msgs, seq, hdrSize)
		if err != nil {
			return nil, err
		}
		managed = append(managed, rules...)
		if done {
			return managed, nil
		}
	}
}

func extractManagedRules(msgs []syscall.NetlinkMessage, seq uint32, hdrSize int) (bool, []kernelRule, error) {
	var managed []kernelRule
	for _, m := range msgs {
		if m.Header.Seq != seq {
			continue
		}
		switch m.Header.Type {
		case unix.NLMSG_DONE:
			return true, managed, nil
		case unix.NLMSG_ERROR:
			if len(m.Data) < 4 {
				return false, nil, errors.New("netlink error")
			}
			code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
			if code == 0 {
				continue
			}
			return false, nil, unix.Errno(-code)
		case unix.RTM_NEWRULE:
			if kr, ok := decodeManagedRule(m.Data, hdrSize); ok {
				managed = append(managed, kr)
			}
		}
	}
	return false, managed, nil
}

func decodeManagedRule(data []byte, hdrSize int) (kernelRule, bool) {
	if len(data) < hdrSize {
		return kernelRule{}, false
	}
	fr := (*fibRuleHdr)(unsafe.Pointer(&data[0]))
	if fr.Family != unix.AF_INET {
		return kernelRule{}, false
	}
	kr := kernelRule{srcLen: int(fr.SrcLen), dstLen: int(fr.DstLen), table: uint32(fr.Table)}
	for _, a := range parseNetlinkAttrs(data[hdrSize:]) {
		switch a.Type {
		case fraPriority:
			if len(a.Value) >= 4 {
				kr.priority = binary.LittleEndian.Uint32(a.Value[:4])
			}
		case fraTable:
			if len(a.Value) >= 4 {
				kr.table = binary.LittleEndian.Uint32(a.Value[:4])
			}
		case fraSrc:
			kr.src = net.IP(append([]byte(nil), a.Value...)).To4()
		case fraDst:
			kr.dst = net.IP(append([]byte(nil), a.Value...)).To4()
		}
	}
	if kr.priority < managedRulePriorityBase || kr.priority > managedRulePriorityMax {
		return kernelRule{}, false
	}
	return kr, true
}

func delRule(r kernelRule) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	seq := atomic.AddUint32(&nlRuleSeq, 1)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_DELRULE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	fr := fibRuleHdr{
		Family: unix.AF_INET,
		DstLen: uint8(r.dstLen),
		SrcLen: uint8(r.srcLen),
		Table:  uint8(r.table),
		Action: frActToTbl,
	}
	_ = binary.Write(&req, binary.LittleEndian, fr)

	prio := make([]byte, 4)
	binary.LittleEndian.PutUint32(prio, r.priority)
	addRtAttr(&req, fraPriority, prio)

	tbl := make([]byte, 4)
	binary.LittleEndian.PutUint32(tbl, r.table)
	addRtAttr(&req, fraTable, tbl)

	if r.src != nil {
		addRtAttr(&req, fraSrc, r.src)
	}
	if r.dst != nil {
		addRtAttr(&req, fraDst, r.dst)
	}

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}
