// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"unsafe"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"golang.org/x/sys/unix"
)

// Reconcile removes local-table takeovers and reasserts the pin, including on
// every ownership reconcile. A single lock serializes scans and netlink events.
func (g *ManagementGuard) Reconcile(ctx context.Context) (err error) {
	if g == nil {
		return nil
	}
	g.reconcileMu.Lock()
	defer g.reconcileMu.Unlock()
	defer func() {
		g.setError(err)
		if err != nil {
			g.fault(ManagementFault{Reason: err.Error()})
		}
	}()
	if err = g.removeSourceAddresses(ctx); err != nil {
		return err
	}
	routes, err := managementDump(ctx, unix.RTM_GETROUTE)
	if err != nil {
		return err
	}
	for _, m := range routes {
		route, ok := parseManagementRoute(m)
		if !ok || route.table != unix.RT_TABLE_LOCAL || route.header.Dst_len != 32 {
			continue
		}
		a, ok := netip.AddrFromSlice(route.dst)
		if !ok || !g.reservation.IsSource(a.Unmap()) {
			continue
		}
		_, err := managementRequest(ctx, unix.RTM_DELROUTE, unix.NLM_F_ACK, route.payload)
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		g.fault(managementAddressFault(route.index, a.String(), "removed source route from kernel local table"))
	}
	return g.ensurePin(ctx, routes)
}
func managementAddressFault(index uint32, address, reason string) ManagementFault {
	f := ManagementFault{Address: address, Reason: reason}
	if nic, err := net.InterfaceByIndex(int(index)); err == nil {
		f.Interface = nic.Name
	}
	// The kernel does not attribute address ownership to a userspace process.
	// Report unknown rather than guessing an owning service from the device name.
	f.Service = "unknown"
	return f
}
func (g *ManagementGuard) removeSourceAddresses(ctx context.Context) error {
	msgs, err := managementDump(ctx, unix.RTM_GETADDR)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWADDR || len(m.Data) < unix.SizeofIfAddrmsg {
			continue
		}
		h := (*unix.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))
		addr, ok := parseInterfaceAddrMessage(m, int(h.Index))
		if !ok {
			continue
		}
		a, ok := netip.AddrFromSlice(addr.IP)
		if !ok || !g.reservation.IsSource(a.Unmap()) {
			continue
		}
		_, err := managementRequest(ctx, unix.RTM_DELADDR, unix.NLM_F_ACK, m.Data)
		if errors.Is(err, unix.EADDRNOTAVAIL) {
			continue
		}
		if err != nil {
			return fmt.Errorf("remove reserved source address %s: %w", a, err)
		}
		g.fault(managementAddressFault(h.Index, a.Unmap().String(), "removed local address equal to reserved source"))
	}
	return nil
}
func (g *ManagementGuard) ensurePin(ctx context.Context, routes []syscall.NetlinkMessage) error {
	r := g.reservation
	nic, err := net.InterfaceByName(r.Device)
	if err != nil {
		return err
	}
	rules, err := managementDump(ctx, unix.RTM_GETRULE)
	if err != nil {
		return err
	}
	for _, source := range r.Sources {
		found := false
		for _, m := range routes {
			rt, ok := parseManagementRoute(m)
			if ok && rt.table == ManagementTable && rt.header.Dst_len == 32 && rt.header.Protocol == ManagementRouteProtocol && rt.header.Scope == unix.RT_SCOPE_LINK && rt.header.Type == unix.RTN_UNICAST && rt.index == uint32(nic.Index) && net.IP(rt.dst).Equal(net.IP(source.AsSlice())) && net.IP(rt.src).Equal(net.IP(r.Local.Addr().AsSlice())) {
				found = true
			}
		}
		if !found {
			var b bytes.Buffer
			b.Write(managementPayload(unix.RtMsg{Family: unix.AF_INET, Dst_len: 32, Protocol: ManagementRouteProtocol, Scope: unix.RT_SCOPE_LINK, Type: unix.RTN_UNICAST}))
			addRtAttr(&b, unix.RTA_DST, source.AsSlice())
			addRtAttr(&b, unix.RTA_PREFSRC, r.Local.Addr().AsSlice())
			managementAttrU32(&b, unix.RTA_OIF, uint32(nic.Index))
			managementAttrU32(&b, unix.RTA_TABLE, ManagementTable)
			if _, err := managementRequest(ctx, unix.RTM_NEWROUTE, unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE, b.Bytes()); err != nil {
				return err
			}
		}
		if !managementPinRuleExists(rules, r, source) {
			var b bytes.Buffer
			b.Write(managementPayload(fibRuleHdr{Family: unix.AF_INET, SrcLen: 32, DstLen: 32, Action: frActToTbl}))
			addRtAttr(&b, fraSrc, r.Local.Addr().AsSlice())
			addRtAttr(&b, fraDst, source.AsSlice())
			managementAttrU32(&b, fraTable, ManagementTable)
			managementAttrU32(&b, fraPriority, mgmtpath.PinPriority)
			if _, err := managementRequest(ctx, unix.RTM_NEWRULE, unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL, b.Bytes()); err != nil {
				return err
			}
		}
	}
	return nil
}
func managementPinRuleExists(msgs []syscall.NetlinkMessage, r *mgmtpath.Reservation, source netip.Addr) bool {
	for _, m := range msgs {
		size := int(unsafe.Sizeof(fibRuleHdr{}))
		if m.Header.Type != unix.RTM_NEWRULE || len(m.Data) < size {
			continue
		}
		h := (*fibRuleHdr)(unsafe.Pointer(&m.Data[0]))
		if h.Family != unix.AF_INET || h.SrcLen != 32 || h.DstLen != 32 || h.Action != frActToTbl {
			continue
		}
		var src, dst net.IP
		table := uint32(h.Table)
		priority := uint32(0)
		for _, a := range parseNetlinkAttrs(m.Data[size:]) {
			switch a.Type {
			case fraSrc:
				src = net.IP(a.Value)
			case fraDst:
				dst = net.IP(a.Value)
			case fraTable:
				if len(a.Value) == 4 {
					table = binary.NativeEndian.Uint32(a.Value)
				}
			case fraPriority:
				if len(a.Value) == 4 {
					priority = binary.NativeEndian.Uint32(a.Value)
				}
			}
		}
		if table == ManagementTable && priority == mgmtpath.PinPriority && src.Equal(net.IP(r.Local.Addr().AsSlice())) && dst.Equal(net.IP(source.AsSlice())) {
			return true
		}
	}
	return false
}

// Kept here rather than in CP: naming conventions are not service authority.
func managementHealth(r *mgmtpath.Reservation) ManagementHealth {
	h := ManagementHealth{Active: true, Device: r.Device, Local: r.Local.String(), Port: r.Port}
	for _, a := range r.Sources {
		h.Sources = append(h.Sources, a.String())
	}
	return h
}

func managementFaultError(err error) ManagementFault {
	return ManagementFault{Reason: "reserved management path netlink guard: " + strings.TrimSpace(err.Error())}
}
