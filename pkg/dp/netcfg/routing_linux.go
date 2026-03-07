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
	"syscall"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

const (
	// routeProtoContaind marks routes installed by containd so we can safely reconcile them.
	// This is a local netns concern (container/appliance); it avoids deleting host/system routes.
	routeProtoContaind = 98

	// managedRulePriorityBase is the default priority base used for auto-assigned rules.
	// We treat this range as "managed by containd" for safe reconcile.
	managedRulePriorityBase = 10000
	managedRulePriorityMax  = 19999
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

func applyRouting(ctx context.Context, routing config.RoutingConfig, opts ApplyRoutingOptions) error {
	if opts.Replace {
		if err := deleteManagedRoutes(ctx); err != nil {
			return err
		}
		if err := deleteManagedRules(ctx); err != nil {
			return err
		}
	}

	gwByName := map[string]config.Gateway{}
	for _, gw := range routing.Gateways {
		name := strings.TrimSpace(gw.Name)
		if name == "" {
			continue
		}
		gwByName[name] = gw
	}

	for _, r := range routing.Routes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := addRoute(r, gwByName); err != nil {
			return err
		}
	}
	for i, rule := range routing.Rules {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := addRule(rule, i); err != nil {
			return err
		}
	}
	return nil
}

func addRoute(r config.StaticRoute, gwByName map[string]config.Gateway) error {
	dst := strings.TrimSpace(r.Dst)
	if strings.EqualFold(dst, "default") {
		dst = "0.0.0.0/0"
	}
	_, ipnet, err := net.ParseCIDR(dst)
	if err != nil || ipnet == nil {
		return fmt.Errorf("route dst invalid %q", r.Dst)
	}
	prefixLen, _ := ipnet.Mask.Size()

	var gw4 net.IP
	gateway := strings.TrimSpace(r.Gateway)
	if gateway != "" {
		gw := net.ParseIP(gateway)
		if gw == nil {
			if named, ok := gwByName[gateway]; ok {
				gw = net.ParseIP(strings.TrimSpace(named.Address))
				if gw == nil || gw.To4() == nil {
					return fmt.Errorf("route gateway %q resolves to invalid IPv4 address", gateway)
				}
				// If the route doesn't specify an interface, prefer the gateway's interface hint.
				if strings.TrimSpace(r.Iface) == "" && strings.TrimSpace(named.Iface) != "" {
					r.Iface = named.Iface
				}
			}
		}
		if gw == nil || gw.To4() == nil {
			return fmt.Errorf("route gateway invalid %q", r.Gateway)
		}
		gw4 = gw.To4()
	}

	ifIndex := 0
	if strings.TrimSpace(r.Iface) != "" {
		nic, err := net.InterfaceByName(strings.TrimSpace(r.Iface))
		if err == nil && nic != nil {
			ifIndex = nic.Index
		}
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
		Type:  unix.RTM_NEWROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)

	table := uint8(unix.RT_TABLE_MAIN)
	if r.Table != 0 {
		table = uint8(r.Table)
	}
	rtm := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  uint8(prefixLen),
		Table:    table,
		Protocol: routeProtoContaind,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	_ = binary.Write(&req, binary.LittleEndian, rtm)

	addRtAttr(&req, unix.RTA_DST, ipnet.IP.To4())
	if ifIndex != 0 {
		oif := make([]byte, 4)
		binary.LittleEndian.PutUint32(oif, uint32(ifIndex))
		addRtAttr(&req, unix.RTA_OIF, oif)
	}
	if gw4 != nil {
		addRtAttr(&req, unix.RTA_GATEWAY, gw4)
	}
	if r.Metric > 0 {
		metric := make([]byte, 4)
		binary.LittleEndian.PutUint32(metric, uint32(r.Metric))
		addRtAttr(&req, unix.RTA_PRIORITY, metric)
	}

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

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

type kernelRoute struct {
	dst     net.IP
	dstLen  int
	gateway net.IP
	ifIndex int
	table   uint8
	metric  uint32
	proto   uint8
}

func deleteManagedRoutes(ctx context.Context) error {
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
		Type:  unix.RTM_GETROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	rtm := unix.RtMsg{Family: unix.AF_INET}
	_ = binary.Write(&req, binary.LittleEndian, rtm)
	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	var managed []kernelRoute
	buf := make([]byte, 1<<16)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
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
			case unix.NLMSG_DONE:
				goto DELETE
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return errors.New("netlink error")
				}
				code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
				if code == 0 {
					continue
				}
				return unix.Errno(-code)
			case unix.RTM_NEWROUTE:
				if len(m.Data) < unix.SizeofRtMsg {
					continue
				}
				rm := (*unix.RtMsg)(unsafe.Pointer(&m.Data[0]))
				if rm.Family != unix.AF_INET {
					continue
				}
				if rm.Protocol != routeProtoContaind {
					continue
				}
				kr := kernelRoute{
					dstLen: int(rm.Dst_len),
					table:  rm.Table,
					proto:  rm.Protocol,
				}
				for _, a := range parseNetlinkAttrs(m.Data[unix.SizeofRtMsg:]) {
					switch a.Type {
					case unix.RTA_DST:
						kr.dst = net.IP(append([]byte(nil), a.Value...)).To4()
					case unix.RTA_GATEWAY:
						kr.gateway = net.IP(append([]byte(nil), a.Value...)).To4()
					case unix.RTA_OIF:
						if len(a.Value) >= 4 {
							kr.ifIndex = int(binary.LittleEndian.Uint32(a.Value[:4]))
						}
					case unix.RTA_PRIORITY:
						if len(a.Value) >= 4 {
							kr.metric = binary.LittleEndian.Uint32(a.Value[:4])
						}
					}
				}
				if kr.dst == nil && kr.dstLen == 0 {
					kr.dst = net.IPv4zero
				}
				if kr.dst == nil {
					continue
				}
				managed = append(managed, kr)
			}
		}
	}

DELETE:
	// Delete managed routes (best-effort). Any newly desired routes will be re-added.
	for _, r := range managed {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := delRoute(r); err != nil {
			// Ignore "not found" style errors.
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
				continue
			}
			return err
		}
	}
	return nil
}

func delRoute(r kernelRoute) error {
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
		Type:  unix.RTM_DELROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	rtm := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  uint8(r.dstLen),
		Table:    r.table,
		Protocol: routeProtoContaind,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	_ = binary.Write(&req, binary.LittleEndian, rtm)

	if r.dstLen > 0 {
		addRtAttr(&req, unix.RTA_DST, r.dst.To4())
	}
	if r.ifIndex != 0 {
		oif := make([]byte, 4)
		binary.LittleEndian.PutUint32(oif, uint32(r.ifIndex))
		addRtAttr(&req, unix.RTA_OIF, oif)
	}
	if r.gateway != nil && !r.gateway.Equal(net.IPv4zero) {
		addRtAttr(&req, unix.RTA_GATEWAY, r.gateway.To4())
	}
	if r.metric != 0 {
		metric := make([]byte, 4)
		binary.LittleEndian.PutUint32(metric, r.metric)
		addRtAttr(&req, unix.RTA_PRIORITY, metric)
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

	var managed []kernelRule
	buf := make([]byte, 1<<16)
	hdrSize := int(unsafe.Sizeof(fibRuleHdr{}))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
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
			case unix.NLMSG_DONE:
				goto DELETE
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return errors.New("netlink error")
				}
				code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
				if code == 0 {
					continue
				}
				return unix.Errno(-code)
			case unix.RTM_NEWRULE:
				if len(m.Data) < hdrSize {
					continue
				}
				fr := (*fibRuleHdr)(unsafe.Pointer(&m.Data[0]))
				if fr.Family != unix.AF_INET {
					continue
				}
				kr := kernelRule{srcLen: int(fr.SrcLen), dstLen: int(fr.DstLen)}
				kr.table = uint32(fr.Table)
				for _, a := range parseNetlinkAttrs(m.Data[hdrSize:]) {
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
					continue
				}
				managed = append(managed, kr)
			}
		}
	}

DELETE:
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

func readNetlinkAck(fd int, seq uint32) error {
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
