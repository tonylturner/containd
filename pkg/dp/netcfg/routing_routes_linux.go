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

func resolveRoute(r config.StaticRoute, gwByName map[string]config.Gateway) (kernelRoute, error) {
	ipnet, prefixLen, err := parseRouteDestination(r.Dst)
	if err != nil {
		return kernelRoute{}, err
	}
	if ipnet.IP.To4() == nil {
		return kernelRoute{}, fmt.Errorf("route dst must be IPv4: %q", r.Dst)
	}
	gw4, ifaceHint, err := resolveRouteGateway(r.Gateway, gwByName)
	if err != nil {
		return kernelRoute{}, err
	}
	if strings.TrimSpace(r.Iface) == "" {
		r.Iface = ifaceHint
	}
	ifIndex := routeInterfaceIndex(r.Iface)
	if strings.TrimSpace(r.Iface) != "" && ifIndex == 0 {
		return kernelRoute{}, fmt.Errorf("route interface not found: %q", r.Iface)
	}
	if r.Table < 0 || r.Table > 252 || r.Metric < 0 {
		return kernelRoute{}, fmt.Errorf("invalid route table or metric")
	}
	table := uint8(unix.RT_TABLE_MAIN)
	if r.Table != 0 {
		table = uint8(r.Table)
	}
	return kernelRoute{dst: ipnet.IP.To4(), dstLen: prefixLen, gateway: gw4, ifIndex: ifIndex, table: uint32(table), metric: uint32(r.Metric), proto: routeProtoContaind}, nil
}

func putRoute(r kernelRoute, replace bool) error {
	fd, err := openRouteNetlinkSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	seq := atomic.AddUint32(&nlSeq, 1)
	ipnet := &net.IPNet{IP: r.dst}
	b := buildAddRouteRequest(seq, ipnet, r.dstLen, uint8(r.table), r.ifIndex, r.gateway, int(r.metric))
	if replace {
		(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Flags = unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE
	}
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readRoutingAck(fd, seq)
}

func parseRouteDestination(dst string) (*net.IPNet, int, error) {
	dst = strings.TrimSpace(dst)
	if strings.EqualFold(dst, "default") {
		dst = "0.0.0.0/0"
	}
	_, ipnet, err := net.ParseCIDR(dst)
	if err != nil || ipnet == nil {
		return nil, 0, fmt.Errorf("route dst invalid %q", dst)
	}
	prefixLen, _ := ipnet.Mask.Size()
	return ipnet, prefixLen, nil
}

func resolveRouteGateway(gateway string, gwByName map[string]config.Gateway) (net.IP, string, error) {
	gateway = strings.TrimSpace(gateway)
	if gateway == "" {
		return nil, "", nil
	}
	gw := net.ParseIP(gateway)
	if gw == nil {
		named, ok := gwByName[gateway]
		if !ok {
			return nil, "", fmt.Errorf("route gateway invalid %q", gateway)
		}
		gw = net.ParseIP(strings.TrimSpace(named.Address))
		if gw == nil || gw.To4() == nil {
			return nil, "", fmt.Errorf("route gateway %q resolves to invalid IPv4 address", gateway)
		}
		return gw.To4(), strings.TrimSpace(named.Iface), nil
	}
	if gw.To4() == nil {
		return nil, "", fmt.Errorf("route gateway invalid %q", gateway)
	}
	return gw.To4(), "", nil
}

func routeInterfaceIndex(iface string) int {
	if strings.TrimSpace(iface) == "" {
		return 0
	}
	nic, err := net.InterfaceByName(strings.TrimSpace(iface))
	if err != nil || nic == nil {
		return 0
	}
	return nic.Index
}

func openRouteNetlinkSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return 0, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return 0, err
	}
	return fd, nil
}

func buildAddRouteRequest(seq uint32, ipnet *net.IPNet, prefixLen int, table uint8, ifIndex int, gw4 net.IP, metric int) []byte {
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_NEWROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.NativeEndian, hdr)
	rtm := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  uint8(prefixLen),
		Table:    table,
		Protocol: routeProtoContaind,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	_ = binary.Write(&req, binary.NativeEndian, rtm)

	addRtAttr(&req, unix.RTA_DST, ipnet.IP.To4())
	if ifIndex != 0 {
		oif := make([]byte, 4)
		binary.NativeEndian.PutUint32(oif, uint32(ifIndex))
		addRtAttr(&req, unix.RTA_OIF, oif)
	}
	if gw4 != nil {
		addRtAttr(&req, unix.RTA_GATEWAY, gw4)
	}
	if metric > 0 {
		buf := make([]byte, 4)
		binary.NativeEndian.PutUint32(buf, uint32(metric))
		addRtAttr(&req, unix.RTA_PRIORITY, buf)
	}

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	return b
}

type kernelRoute struct {
	dst     net.IP
	dstLen  int
	gateway net.IP
	ifIndex int
	table   uint32
	metric  uint32
	proto   uint8
	tos     uint8
	raw     []byte
}

func kernelRoutes(ctx context.Context) ([]kernelRoute, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	seq := atomic.AddUint32(&nlSeq, 1)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_GETROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.NativeEndian, hdr)
	rtm := unix.RtMsg{Family: unix.AF_INET}
	_ = binary.Write(&req, binary.NativeEndian, rtm)
	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	return listKernelRoutes(ctx, fd, seq)
}

func listKernelRoutes(ctx context.Context, fd int, seq uint32) ([]kernelRoute, error) {
	var managed []kernelRoute
	buf := make([]byte, 1<<16)
	for {
		msgs, err := recvRouteMessages(ctx, fd, buf)
		if err != nil {
			return nil, err
		}
		done, routes, err := extractKernelRoutes(msgs, seq)
		if err != nil {
			return nil, err
		}
		managed = append(managed, routes...)
		if done {
			return managed, nil
		}
	}
}

func recvRouteMessages(ctx context.Context, fd int, buf []byte) ([]syscall.NetlinkMessage, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, err
	}
	return syscall.ParseNetlinkMessage(buf[:n])
}

func extractKernelRoutes(msgs []syscall.NetlinkMessage, seq uint32) (bool, []kernelRoute, error) {
	var managed []kernelRoute
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
			code := int32(binary.NativeEndian.Uint32(m.Data[:4]))
			if code == 0 {
				continue
			}
			return false, nil, unix.Errno(-code)
		case unix.RTM_NEWROUTE:
			if kr, ok := decodeKernelRoute(m.Data); ok {
				managed = append(managed, kr)
			}
		}
	}
	return false, managed, nil
}

func decodeKernelRoute(data []byte) (kernelRoute, bool) {
	if len(data) < unix.SizeofRtMsg {
		return kernelRoute{}, false
	}
	rm := (*unix.RtMsg)(unsafe.Pointer(&data[0]))
	if rm.Family != unix.AF_INET {
		return kernelRoute{}, false
	}
	kr := kernelRoute{
		dstLen: int(rm.Dst_len),
		table:  uint32(rm.Table),
		tos:    rm.Tos,
		raw:    append([]byte(nil), data...),
		proto:  rm.Protocol,
	}
	for _, a := range parseNetlinkAttrs(data[unix.SizeofRtMsg:]) {
		switch a.Type {
		case unix.RTA_DST:
			kr.dst = net.IP(append([]byte(nil), a.Value...)).To4()
		case unix.RTA_GATEWAY:
			kr.gateway = net.IP(append([]byte(nil), a.Value...)).To4()
		case unix.RTA_OIF:
			if len(a.Value) >= 4 {
				kr.ifIndex = int(binary.NativeEndian.Uint32(a.Value[:4]))
			}
		case unix.RTA_TABLE:
			if len(a.Value) >= 4 {
				kr.table = binary.NativeEndian.Uint32(a.Value[:4])
			}
		case unix.RTA_PRIORITY:
			if len(a.Value) >= 4 {
				kr.metric = binary.NativeEndian.Uint32(a.Value[:4])
			}
		}
	}
	if kr.dst == nil && kr.dstLen == 0 {
		kr.dst = net.IPv4zero
	}
	return kr, kr.dst != nil
}

func deleteKernelRoutes(ctx context.Context, managed []kernelRoute) error {
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
	_ = binary.Write(&req, binary.NativeEndian, hdr)
	rtm := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  uint8(r.dstLen),
		Table:    uint8(r.table),
		Protocol: routeProtoContaind,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	_ = binary.Write(&req, binary.NativeEndian, rtm)

	if r.dstLen > 0 {
		addRtAttr(&req, unix.RTA_DST, r.dst.To4())
	}
	if r.ifIndex != 0 {
		oif := make([]byte, 4)
		binary.NativeEndian.PutUint32(oif, uint32(r.ifIndex))
		addRtAttr(&req, unix.RTA_OIF, oif)
	}
	if r.gateway != nil && !r.gateway.Equal(net.IPv4zero) {
		addRtAttr(&req, unix.RTA_GATEWAY, r.gateway.To4())
	}
	if r.metric != 0 {
		metric := make([]byte, 4)
		binary.NativeEndian.PutUint32(metric, r.metric)
		addRtAttr(&req, unix.RTA_PRIORITY, metric)
	}

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}
