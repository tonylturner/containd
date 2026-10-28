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
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var gateRoutingMu sync.Mutex

var gateFamilies = []uint8{unix.AF_INET, unix.AF_INET6}

// EnsureGateRouting installs, for IPv4 and IPv6, the policy rule and the
// local route that deliver packets carrying GateLocalMark to this host. It
// is idempotent: an exact object is kept, any other rule or route carrying
// GateRouteProtocol in GateRoutingTable is replaced, and objects with another
// protocol, including the management pin, are never touched.
func EnsureGateRouting(ctx context.Context) error {
	return reconcileGateRouting(ctx, true)
}

// RemoveGateRouting deletes every rule and route carrying GateRouteProtocol
// in GateRoutingTable for IPv4 and IPv6 and nothing else.
func RemoveGateRouting(ctx context.Context) error {
	return reconcileGateRouting(ctx, false)
}

func reconcileGateRouting(ctx context.Context, install bool) error {
	gateRoutingMu.Lock()
	defer gateRoutingMu.Unlock()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("gate routing: %w", err)
	}
	for _, family := range gateFamilies {
		// The rule only ever points at a populated table, and removal leaves
		// no rule looking up a table whose route is already gone.
		steps := []func() error{
			func() error { return reconcileGateRoute(ctx, family, uint32(lo.Index), install) },
			func() error { return reconcileGateRule(ctx, family, install) },
		}
		if !install {
			steps[0], steps[1] = steps[1], steps[0]
		}
		for _, step := range steps {
			if err := step(); err != nil {
				return fmt.Errorf("gate routing %s: %w", gateFamilyName(family), err)
			}
		}
	}
	return nil
}

func gateFamilyName(family uint8) string {
	if family == unix.AF_INET6 {
		return "IPv6"
	}
	return "IPv4"
}

// gateRule is the subset of a kernel policy rule that identifies gate
// ownership (proto, table) and exactness (everything else).
type gateRule struct {
	family   uint8
	proto    uint8
	priority uint32
	table    uint32
	fwmark   uint32
	fwmask   uint32
	// exact is false when the rule carries any selector, flag or attribute
	// beyond priority, mark, table and protocol.
	exact   bool
	payload []byte
}

func (r gateRule) owned() bool {
	return r.proto == GateRouteProtocol && r.table == GateRoutingTable
}

func (r gateRule) wanted(family uint8) bool {
	return r.exact && r.family == family && r.owned() && r.priority == GateRulePriority && r.fwmark == GateLocalMark && r.fwmask == GateLocalMark
}

func gateRulePayload(family uint8) []byte {
	var b bytes.Buffer
	// Tables above 255 travel in FRA_TABLE; the header table stays unspecified.
	b.Write(netlinkPayload(fibRuleHdr{Family: family, Table: unix.RT_TABLE_UNSPEC, Action: frActToTbl}))
	netlinkAttrU32(&b, unix.FRA_PRIORITY, GateRulePriority)
	netlinkAttrU32(&b, unix.FRA_FWMARK, GateLocalMark)
	netlinkAttrU32(&b, unix.FRA_FWMASK, GateLocalMark)
	netlinkAttrU32(&b, unix.FRA_TABLE, GateRoutingTable)
	addRtAttr(&b, unix.FRA_PROTOCOL, []byte{GateRouteProtocol})
	return b.Bytes()
}

func decodeGateRule(m syscall.NetlinkMessage) (gateRule, bool) {
	size := int(unsafe.Sizeof(fibRuleHdr{}))
	if m.Header.Type != unix.RTM_NEWRULE || len(m.Data) < size {
		return gateRule{}, false
	}
	h := *(*fibRuleHdr)(unsafe.Pointer(&m.Data[0]))
	r := gateRule{family: h.Family, table: uint32(h.Table), payload: m.Data, exact: h.Action == frActToTbl && h.SrcLen == 0 && h.DstLen == 0 && h.Tos == 0 && h.Flags == 0}
	for _, a := range parseNetlinkAttrs(m.Data[size:]) {
		switch a.Type {
		case unix.FRA_PRIORITY:
			r.priority = gateAttrU32(a)
		case unix.FRA_TABLE:
			r.table = gateAttrU32(a)
		case unix.FRA_FWMARK:
			r.fwmark = gateAttrU32(a)
		case unix.FRA_FWMASK:
			r.fwmask = gateAttrU32(a)
		case unix.FRA_PROTOCOL:
			if len(a.Value) == 1 {
				r.proto = a.Value[0]
			}
		case unix.FRA_PAD:
		case unix.FRA_SUPPRESS_PREFIXLEN, unix.FRA_SUPPRESS_IFGROUP:
			// Dumps carry the unset suppressors as -1.
			if gateAttrU32(a) != ^uint32(0) {
				r.exact = false
			}
		default:
			r.exact = false
		}
	}
	return r, true
}

func gateAttrU32(a netlinkAttr) uint32 {
	if len(a.Value) != 4 {
		return 0
	}
	return binary.NativeEndian.Uint32(a.Value)
}

func reconcileGateRule(ctx context.Context, family uint8, install bool) error {
	msgs, err := netlinkRequest(ctx, unix.RTM_GETRULE, unix.NLM_F_DUMP, netlinkPayload(fibRuleHdr{Family: family}))
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	present := false
	for _, m := range msgs {
		r, ok := decodeGateRule(m)
		if !ok || r.family != family || !r.owned() {
			continue
		}
		if install && !present && r.wanted(family) {
			present = true
			continue
		}
		if err := gateDelete(ctx, unix.RTM_DELRULE, r.payload); err != nil {
			return fmt.Errorf("delete rule: %w", err)
		}
	}
	if !install || present {
		return nil
	}
	if _, err := netlinkRequest(ctx, unix.RTM_NEWRULE, unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL, gateRulePayload(family)); err != nil {
		return fmt.Errorf("add rule: %w", err)
	}
	return nil
}

// gateRoute is the subset of a kernel route that identifies gate ownership
// (proto, table) and the wanted local default route via lo.
type gateRoute struct {
	family  uint8
	kind    uint8
	proto   uint8
	dstLen  uint8
	table   uint32
	oif     uint32
	payload []byte
}

func (r gateRoute) owned() bool {
	return r.proto == GateRouteProtocol && r.table == GateRoutingTable
}

func (r gateRoute) wanted(family uint8, lo uint32) bool {
	return r.family == family && r.owned() && r.kind == unix.RTN_LOCAL && r.dstLen == 0 && r.oif == lo
}

func gateRoutePayload(family uint8, lo uint32) []byte {
	var b bytes.Buffer
	b.Write(netlinkPayload(unix.RtMsg{Family: family, Table: unix.RT_TABLE_UNSPEC, Protocol: GateRouteProtocol, Scope: unix.RT_SCOPE_HOST, Type: unix.RTN_LOCAL}))
	netlinkAttrU32(&b, unix.RTA_TABLE, GateRoutingTable)
	netlinkAttrU32(&b, unix.RTA_OIF, lo)
	return b.Bytes()
}

func decodeGateRoute(m syscall.NetlinkMessage) (gateRoute, bool) {
	if m.Header.Type != unix.RTM_NEWROUTE || len(m.Data) < unix.SizeofRtMsg {
		return gateRoute{}, false
	}
	h := *(*unix.RtMsg)(unsafe.Pointer(&m.Data[0]))
	r := gateRoute{family: h.Family, kind: h.Type, proto: h.Protocol, dstLen: h.Dst_len, table: uint32(h.Table), payload: m.Data}
	for _, a := range parseNetlinkAttrs(m.Data[unix.SizeofRtMsg:]) {
		switch a.Type {
		case unix.RTA_TABLE:
			r.table = gateAttrU32(a)
		case unix.RTA_OIF:
			r.oif = gateAttrU32(a)
		}
	}
	return r, true
}

func reconcileGateRoute(ctx context.Context, family uint8, lo uint32, install bool) error {
	msgs, err := netlinkRequest(ctx, unix.RTM_GETROUTE, unix.NLM_F_DUMP, netlinkPayload(unix.RtMsg{Family: family}))
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	present := false
	for _, m := range msgs {
		r, ok := decodeGateRoute(m)
		if !ok || r.family != family || !r.owned() {
			continue
		}
		if install && !present && r.wanted(family, lo) {
			present = true
			continue
		}
		if err := gateDelete(ctx, unix.RTM_DELROUTE, r.payload); err != nil {
			return fmt.Errorf("delete route: %w", err)
		}
	}
	if !install || present {
		return nil
	}
	if _, err := netlinkRequest(ctx, unix.RTM_NEWROUTE, unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL, gateRoutePayload(family, lo)); err != nil {
		return fmt.Errorf("add route: %w", err)
	}
	return nil
}

// gateDelete replays a dumped object as its own deletion, so a stale variant
// is removed exactly as the kernel reported it. An object that vanished in
// the meantime is already in the wanted state.
func gateDelete(ctx context.Context, kind uint16, payload []byte) error {
	_, err := netlinkRequest(ctx, kind, unix.NLM_F_ACK, payload)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}
