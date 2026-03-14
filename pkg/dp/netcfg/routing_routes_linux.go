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

func addRoute(r config.StaticRoute, gwByName map[string]config.Gateway) error {
	ipnet, prefixLen, err := parseRouteDestination(r.Dst)
	if err != nil {
		return err
	}
	gw4, ifaceHint, err := resolveRouteGateway(r.Gateway, gwByName)
	if err != nil {
		return err
	}
	if strings.TrimSpace(r.Iface) == "" && ifaceHint != "" {
		r.Iface = ifaceHint
	}
	ifIndex := routeInterfaceIndex(r.Iface)
	fd, err := openRouteNetlinkSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	seq := atomic.AddUint32(&nlSeq, 1)
	table := uint8(unix.RT_TABLE_MAIN)
	if r.Table != 0 {
		table = uint8(r.Table)
	}
	b := buildAddRouteRequest(seq, ipnet, prefixLen, table, ifIndex, gw4, r.Metric)
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	if err := readNetlinkAck(fd, seq); err != nil {
		if isSysctlWriteBlocked(err) {
			exists, existsErr := routeExists(kernelRoute{
				dst:     ipnet.IP.To4(),
				dstLen:  prefixLen,
				gateway: gw4,
				ifIndex: ifIndex,
				table:   table,
				metric:  uint32(r.Metric),
			})
			if existsErr == nil && exists {
				return nil
			}
		}
		return err
	}
	return nil
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
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
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
	if metric > 0 {
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(metric))
		addRtAttr(&req, unix.RTA_PRIORITY, buf)
	}

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	return b
}

func routeExists(want kernelRoute) (bool, error) {
	fd, err := openRouteNetlinkSocket()
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)

	seq := atomic.AddUint32(&nlSeq, 1)
	b := buildRouteDumpRequest(seq)
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return false, err
	}

	buf := make([]byte, 1<<16)
	for {
		msgs, err := recvRouteMessages(context.Background(), fd, buf)
		if err != nil {
			return false, err
		}
		done, found, err := routeExistsInMessages(msgs, seq, want)
		if err != nil {
			return false, err
		}
		if found || done {
			return found, nil
		}
	}
}

func buildRouteDumpRequest(seq uint32) []byte {
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
	return b
}

func routeExistsInMessages(msgs []syscall.NetlinkMessage, seq uint32, want kernelRoute) (bool, bool, error) {
	for _, m := range msgs {
		if m.Header.Seq != seq {
			continue
		}
		switch m.Header.Type {
		case unix.NLMSG_DONE:
			return true, false, nil
		case unix.NLMSG_ERROR:
			if len(m.Data) < 4 {
				return false, false, errors.New("netlink error")
			}
			code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
			if code == 0 {
				continue
			}
			return false, false, unix.Errno(-code)
		case unix.RTM_NEWROUTE:
			got, ok := decodeKernelRoute(m.Data)
			if ok && routesEqual(got, want) {
				return false, true, nil
			}
		}
	}
	return false, false, nil
}

func decodeKernelRoute(data []byte) (kernelRoute, bool) {
	if len(data) < unix.SizeofRtMsg {
		return kernelRoute{}, false
	}
	rm := (*unix.RtMsg)(unsafe.Pointer(&data[0]))
	if rm.Family != unix.AF_INET {
		return kernelRoute{}, false
	}
	got := kernelRoute{
		dstLen: int(rm.Dst_len),
		table:  rm.Table,
	}
	for _, a := range parseNetlinkAttrs(data[unix.SizeofRtMsg:]) {
		switch a.Type {
		case unix.RTA_DST:
			got.dst = net.IP(append([]byte(nil), a.Value...)).To4()
		case unix.RTA_GATEWAY:
			got.gateway = net.IP(append([]byte(nil), a.Value...)).To4()
		case unix.RTA_OIF:
			if len(a.Value) >= 4 {
				got.ifIndex = int(binary.LittleEndian.Uint32(a.Value[:4]))
			}
		case unix.RTA_PRIORITY:
			if len(a.Value) >= 4 {
				got.metric = binary.LittleEndian.Uint32(a.Value[:4])
			}
		}
	}
	if got.dst == nil && got.dstLen == 0 {
		got.dst = net.IPv4zero
	}
	return got, true
}

func routesEqual(got, want kernelRoute) bool {
	if got.dstLen != want.dstLen || got.table != want.table {
		return false
	}
	if want.dstLen == 0 {
		if got.dst == nil || !got.dst.Equal(net.IPv4zero) {
			return false
		}
	} else if got.dst == nil || want.dst == nil || !got.dst.Equal(want.dst) {
		return false
	}
	if want.gateway != nil && (got.gateway == nil || !got.gateway.Equal(want.gateway)) {
		return false
	}
	if want.ifIndex != 0 && got.ifIndex != want.ifIndex {
		return false
	}
	if want.metric != 0 && got.metric != want.metric {
		return false
	}
	return true
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

	managed, err := listManagedRoutes(ctx, fd, seq)
	if err != nil {
		return err
	}
	return deleteKernelRoutes(ctx, managed)
}

func listManagedRoutes(ctx context.Context, fd int, seq uint32) ([]kernelRoute, error) {
	var managed []kernelRoute
	buf := make([]byte, 1<<16)
	for {
		msgs, err := recvRouteMessages(ctx, fd, buf)
		if err != nil {
			return nil, err
		}
		done, routes, err := extractManagedRoutes(msgs, seq)
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

func extractManagedRoutes(msgs []syscall.NetlinkMessage, seq uint32) (bool, []kernelRoute, error) {
	var managed []kernelRoute
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
		case unix.RTM_NEWROUTE:
			if kr, ok := decodeManagedRoute(m.Data); ok {
				managed = append(managed, kr)
			}
		}
	}
	return false, managed, nil
}

func decodeManagedRoute(data []byte) (kernelRoute, bool) {
	if len(data) < unix.SizeofRtMsg {
		return kernelRoute{}, false
	}
	rm := (*unix.RtMsg)(unsafe.Pointer(&data[0]))
	if rm.Family != unix.AF_INET || rm.Protocol != routeProtoContaind {
		return kernelRoute{}, false
	}
	kr := kernelRoute{
		dstLen: int(rm.Dst_len),
		table:  rm.Table,
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
