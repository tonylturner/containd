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

	"github.com/containd/containd/pkg/cp/config"
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

func applyRouting(ctx context.Context, routing config.RoutingConfig, opts ApplyRoutingOptions) error {
	_ = opts // replace semantics are future; additive apply is sufficient for now.

	for _, r := range routing.Routes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := addRoute(r); err != nil {
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

func addRoute(r config.StaticRoute) error {
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
	if strings.TrimSpace(r.Gateway) != "" {
		gw := net.ParseIP(strings.TrimSpace(r.Gateway))
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
		Protocol: unix.RTPROT_STATIC,
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
		priority = 10000 + idx
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
