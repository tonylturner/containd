// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"encoding/binary"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func unsafePointer(b []byte) unsafe.Pointer { return unsafe.Pointer(&b[0]) }

func gateDumpMessage(kind uint16, payload []byte) syscall.NetlinkMessage {
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: kind}, Data: payload}
}

func TestGateRuleRoundTripIsWanted(t *testing.T) {
	t.Parallel()
	for _, family := range gateFamilies {
		// The kernel echoes the unset suppressor and padding in every dump.
		payload := append([]byte(nil), gateRulePayload(family)...)
		var extra bytes.Buffer
		managementAttrU32(&extra, unix.FRA_SUPPRESS_PREFIXLEN, ^uint32(0))
		addRtAttr(&extra, unix.FRA_PAD, nil)
		payload = append(payload, extra.Bytes()...)
		r, ok := decodeGateRule(gateDumpMessage(unix.RTM_NEWRULE, payload))
		if !ok || !r.owned() || !r.wanted(family) {
			t.Fatalf("family %d: decoded %+v ok=%v, want owned and wanted", family, r, ok)
		}
		other := uint8(unix.AF_INET6)
		if family == unix.AF_INET6 {
			other = unix.AF_INET
		}
		if r.wanted(other) {
			t.Fatalf("family %d: rule wanted for the other family", family)
		}
		if _, ok := decodeGateRule(gateDumpMessage(unix.RTM_DELRULE, payload)); ok {
			t.Fatal("decoded a non-dump message")
		}
	}
}

func TestGateRuleOwnershipAndExactness(t *testing.T) {
	t.Parallel()
	build := func(hdr fibRuleHdr, attrs func(*bytes.Buffer)) gateRule {
		t.Helper()
		var b bytes.Buffer
		b.Write(managementPayload(hdr))
		attrs(&b)
		r, ok := decodeGateRule(gateDumpMessage(unix.RTM_NEWRULE, b.Bytes()))
		if !ok {
			t.Fatal("decode failed")
		}
		return r
	}
	wantedAttrs := func(proto uint8, table, priority, mark, mask uint32) func(*bytes.Buffer) {
		return func(b *bytes.Buffer) {
			managementAttrU32(b, unix.FRA_PRIORITY, priority)
			managementAttrU32(b, unix.FRA_FWMARK, mark)
			managementAttrU32(b, unix.FRA_FWMASK, mask)
			managementAttrU32(b, unix.FRA_TABLE, table)
			addRtAttr(b, unix.FRA_PROTOCOL, []byte{proto})
		}
	}
	base := fibRuleHdr{Family: unix.AF_INET, Action: frActToTbl}
	// The management pin and containd config rules share priority 1 or the
	// table range but never both protocol and table.
	for name, r := range map[string]gateRule{
		"management pin": build(fibRuleHdr{Family: unix.AF_INET, SrcLen: 32, DstLen: 32, Action: frActToTbl}, func(b *bytes.Buffer) {
			managementAttrU32(b, unix.FRA_TABLE, ManagementTable)
			managementAttrU32(b, unix.FRA_PRIORITY, 1)
		}),
		"containd config":        build(base, wantedAttrs(routeProtoContaind, GateRoutingTable, GateRulePriority, GateLocalMark, GateLocalMark)),
		"foreign same table":     build(base, wantedAttrs(unix.RTPROT_STATIC, GateRoutingTable, 5, 2, 2)),
		"gate proto other table": build(base, wantedAttrs(GateRouteProtocol, 201, GateRulePriority, GateLocalMark, GateLocalMark)),
	} {
		if r.owned() {
			t.Fatalf("%s: %+v must not be owned", name, r)
		}
	}
	// Owned variants are replaced: wrong priority, mark, mask, selector,
	// flag or an attribute the gate never sets.
	for name, r := range map[string]gateRule{
		"priority":    build(base, wantedAttrs(GateRouteProtocol, GateRoutingTable, 7, GateLocalMark, GateLocalMark)),
		"mark":        build(base, wantedAttrs(GateRouteProtocol, GateRoutingTable, GateRulePriority, 1, 1)),
		"mask":        build(base, wantedAttrs(GateRouteProtocol, GateRoutingTable, GateRulePriority, GateLocalMark, 0xffffffff)),
		"selector":    build(fibRuleHdr{Family: unix.AF_INET, DstLen: 24, Action: frActToTbl}, wantedAttrs(GateRouteProtocol, GateRoutingTable, GateRulePriority, GateLocalMark, GateLocalMark)),
		"invert flag": build(fibRuleHdr{Family: unix.AF_INET, Action: frActToTbl, Flags: 1}, wantedAttrs(GateRouteProtocol, GateRoutingTable, GateRulePriority, GateLocalMark, GateLocalMark)),
		"input device": build(base, func(b *bytes.Buffer) {
			wantedAttrs(GateRouteProtocol, GateRoutingTable, GateRulePriority, GateLocalMark, GateLocalMark)(b)
			addRtAttr(b, unix.FRA_IIFNAME, []byte("lo\x00"))
		}),
		"suppress set": build(base, func(b *bytes.Buffer) {
			wantedAttrs(GateRouteProtocol, GateRoutingTable, GateRulePriority, GateLocalMark, GateLocalMark)(b)
			managementAttrU32(b, unix.FRA_SUPPRESS_PREFIXLEN, 8)
		}),
		"header table": build(fibRuleHdr{Family: unix.AF_INET, Table: 201, Action: frActToTbl}, func(b *bytes.Buffer) {
			managementAttrU32(b, unix.FRA_PRIORITY, GateRulePriority)
			managementAttrU32(b, unix.FRA_FWMARK, GateLocalMark)
			managementAttrU32(b, unix.FRA_FWMASK, GateLocalMark)
			managementAttrU32(b, unix.FRA_TABLE, GateRoutingTable)
			addRtAttr(b, unix.FRA_PROTOCOL, []byte{GateRouteProtocol})
		}),
	} {
		if !r.owned() {
			t.Fatalf("%s: %+v must be owned", name, r)
		}
		if name != "header table" && r.wanted(unix.AF_INET) {
			t.Fatalf("%s: %+v must not be wanted", name, r)
		}
		if name == "header table" && !r.wanted(unix.AF_INET) {
			t.Fatalf("%s: FRA_TABLE must override the truncated header table: %+v", name, r)
		}
	}
}

func TestGateRouteRoundTripIsWanted(t *testing.T) {
	t.Parallel()
	const lo = 1
	for _, family := range gateFamilies {
		payload := append([]byte(nil), gateRoutePayload(family, lo)...)
		var extra bytes.Buffer
		managementAttrU32(&extra, unix.RTA_PRIORITY, 1024)
		payload = append(payload, extra.Bytes()...)
		r, ok := decodeGateRoute(gateDumpMessage(unix.RTM_NEWROUTE, payload))
		if !ok || !r.owned() || !r.wanted(family, lo) {
			t.Fatalf("family %d: decoded %+v ok=%v, want owned and wanted", family, r, ok)
		}
		if r.wanted(family, lo+1) {
			t.Fatal("route via another device wanted")
		}
	}
	hdr := unix.RtMsg{Family: unix.AF_INET, Table: unix.RT_TABLE_COMPAT, Protocol: GateRouteProtocol, Scope: unix.RT_SCOPE_HOST, Type: unix.RTN_LOCAL}
	for name, c := range map[string]struct {
		hdr   unix.RtMsg
		table uint32
		owned bool
	}{
		"compat header with gate table":    {hdr: hdr, table: GateRoutingTable, owned: true},
		"gate proto in other table":        {hdr: hdr, table: 201, owned: false},
		"management route in gate table":   {hdr: unix.RtMsg{Family: unix.AF_INET, Protocol: ManagementRouteProtocol, Type: unix.RTN_UNICAST}, table: GateRoutingTable, owned: false},
		"containd route in gate table":     {hdr: unix.RtMsg{Family: unix.AF_INET, Protocol: routeProtoContaind, Type: unix.RTN_UNICAST}, table: GateRoutingTable, owned: false},
		"unicast gate route is not wanted": {hdr: unix.RtMsg{Family: unix.AF_INET, Protocol: GateRouteProtocol, Type: unix.RTN_UNICAST}, table: GateRoutingTable, owned: true},
	} {
		var b bytes.Buffer
		b.Write(managementPayload(c.hdr))
		managementAttrU32(&b, unix.RTA_TABLE, c.table)
		managementAttrU32(&b, unix.RTA_OIF, lo)
		r, ok := decodeGateRoute(gateDumpMessage(unix.RTM_NEWROUTE, b.Bytes()))
		if !ok || r.owned() != c.owned {
			t.Fatalf("%s: decoded %+v ok=%v, want owned=%v", name, r, ok, c.owned)
		}
		if r.wanted(unix.AF_INET, lo) != (c.owned && c.hdr.Type == unix.RTN_LOCAL) {
			t.Fatalf("%s: wanted=%v for %+v", name, r.wanted(unix.AF_INET, lo), r)
		}
	}
	prefixed := append([]byte(nil), gateRoutePayload(unix.AF_INET, lo)...)
	(*unix.RtMsg)(unsafePointer(prefixed)).Dst_len = 24
	if r, ok := decodeGateRoute(gateDumpMessage(unix.RTM_NEWROUTE, prefixed)); !ok || !r.owned() || r.wanted(unix.AF_INET, lo) {
		t.Fatalf("prefixed local route must be owned but not wanted: %+v", r)
	}
}

func TestGateRulePayloadCarriesTableInAttribute(t *testing.T) {
	t.Parallel()
	payload := gateRulePayload(unix.AF_INET6)
	hdr := *(*fibRuleHdr)(unsafePointer(payload))
	if hdr.Table != unix.RT_TABLE_UNSPEC || hdr.Family != unix.AF_INET6 || hdr.Action != frActToTbl {
		t.Fatalf("header %+v", hdr)
	}
	seen := map[uint16][]byte{}
	for _, a := range parseNetlinkAttrs(payload[binary.Size(fibRuleHdr{}):]) {
		seen[a.Type] = a.Value
	}
	if got := binary.NativeEndian.Uint32(seen[unix.FRA_TABLE]); got != GateRoutingTable {
		t.Fatalf("FRA_TABLE = %d", got)
	}
	if got := seen[unix.FRA_PROTOCOL]; len(got) != 1 || got[0] != GateRouteProtocol {
		t.Fatalf("FRA_PROTOCOL = %v", got)
	}
}
