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
	fraProtocol = 21
)

var nlRuleSeq uint32

func resolveRule(r config.PolicyRule, idx int) (kernelRule, error) {
	if r.Table <= 0 || r.Table > 252 {
		return kernelRule{}, fmt.Errorf("rule table out of range: %d", r.Table)
	}
	priority := r.Priority
	if priority == 0 {
		priority = managedRulePriorityBase + idx
	}

	if priority < 1 || priority > 65535 {
		return kernelRule{}, fmt.Errorf("rule priority out of range: %d", priority)
	}

	var srcIP, dstIP net.IP
	var srcLen, dstLen int
	if strings.TrimSpace(r.Src) != "" {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(r.Src))
		if err != nil || ipnet == nil || ipnet.IP == nil {
			return kernelRule{}, fmt.Errorf("rule src invalid %q", r.Src)
		}
		srcIP = ipnet.IP.To4()
		if srcIP == nil {
			return kernelRule{}, fmt.Errorf("rule src must be IPv4 for now: %q", r.Src)
		}
		srcLen, _ = ipnet.Mask.Size()
	}
	if strings.TrimSpace(r.Dst) != "" {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(r.Dst))
		if err != nil || ipnet == nil || ipnet.IP == nil {
			return kernelRule{}, fmt.Errorf("rule dst invalid %q", r.Dst)
		}
		dstIP = ipnet.IP.To4()
		if dstIP == nil {
			return kernelRule{}, fmt.Errorf("rule dst must be IPv4 for now: %q", r.Dst)
		}
		dstLen, _ = ipnet.Mask.Size()
	}

	if srcLen == 0 {
		srcIP = nil
	}
	if dstLen == 0 {
		dstIP = nil
	}
	return kernelRule{priority: uint32(priority), table: uint32(r.Table), src: srcIP, srcLen: srcLen, dst: dstIP, dstLen: dstLen, proto: routeProtoContaind, simple: true}, nil
}

func addRule(r kernelRule) error {
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
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
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

	addRtAttr(&req, fraProtocol, []byte{r.proto})

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readRoutingAck(fd, seq)
}

type kernelRule struct {
	proto    uint8
	simple   bool
	priority uint32
	table    uint32
	src      net.IP
	srcLen   int
	dst      net.IP
	dstLen   int
}

func kernelRules(ctx context.Context) ([]kernelRule, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
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
		return nil, err
	}

	return listKernelRules(ctx, fd, seq)
}

func listKernelRules(ctx context.Context, fd int, seq uint32) ([]kernelRule, error) {
	var managed []kernelRule
	buf := make([]byte, 1<<16)
	hdrSize := int(unsafe.Sizeof(fibRuleHdr{}))
	for {
		msgs, err := recvRouteMessages(ctx, fd, buf)
		if err != nil {
			return nil, err
		}
		done, rules, err := extractKernelRules(msgs, seq, hdrSize)
		if err != nil {
			return nil, err
		}
		managed = append(managed, rules...)
		if done {
			return managed, nil
		}
	}
}

func extractKernelRules(msgs []syscall.NetlinkMessage, seq uint32, hdrSize int) (bool, []kernelRule, error) {
	var managed []kernelRule
	for _, m := range msgs {
		if m.Header.Seq != seq {
			continue
		}
		if err := routeDumpError(m); err != nil {
			return false, nil, err
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
			if kr, ok := decodeKernelRule(m.Data, hdrSize); ok {
				managed = append(managed, kr)
			}
		}
	}
	return false, managed, nil
}

func decodeKernelRule(data []byte, hdrSize int) (kernelRule, bool) {
	if len(data) < hdrSize {
		return kernelRule{}, false
	}
	fr := (*fibRuleHdr)(unsafe.Pointer(&data[0]))
	if fr.Family != unix.AF_INET {
		return kernelRule{}, false
	}
	kr := kernelRule{srcLen: int(fr.SrcLen), dstLen: int(fr.DstLen), table: uint32(fr.Table), simple: fr.Action == frActToTbl && fr.Tos == 0 && fr.Flags == 0}
	for _, a := range parseNetlinkAttrs(data[hdrSize:]) {
		switch a.Type {
		case fraProtocol:
			if len(a.Value) == 1 {
				kr.proto = a.Value[0]
			}
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
		default:
			// Kernel dumps include default suppress-prefixlen and padding attributes.
			if a.Type != unix.FRA_PAD && !(a.Type == unix.FRA_SUPPRESS_PREFIXLEN && len(a.Value) == 4 && binary.LittleEndian.Uint32(a.Value) == ^uint32(0)) {
				kr.simple = false
			}
		}
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

	addRtAttr(&req, fraProtocol, []byte{r.proto})

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}
