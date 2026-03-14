// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

func protocolPortMatches(entry rules.Entry, p rules.Protocol, state *flow.State, pkt *dpi.ParsedPacket) bool {
	if p.Name != "" && !strings.EqualFold(p.Name, pkt.Proto) {
		return false
	}
	port := servicePort(state, pkt)
	if p.Port == "" {
		// Any port for that transport.
		return true
	}
	min, max, ok := parsePortRange(p.Port)
	if !ok {
		return false
	}
	return port >= min && port <= max
}

// isExcluded checks whether either endpoint of a flow matches a DPI exclusion.
func (e *Engine) isExcluded(state *flow.State) bool {
	for _, excl := range e.dpiExclusions {
		switch excl.Type {
		case "ip":
			ip := net.ParseIP(excl.Value)
			if ip == nil {
				continue
			}
			if state.Key.SrcIP.Equal(ip) || state.Key.DstIP.Equal(ip) {
				return true
			}
		case "cidr":
			_, cidr, err := net.ParseCIDR(excl.Value)
			if err != nil {
				continue
			}
			if cidr.Contains(state.Key.SrcIP) || cidr.Contains(state.Key.DstIP) {
				return true
			}
		case "domain":
			// Domain exclusions are matched against flow metadata if available.
			// In practice, DNS responses populate flow state with resolved names.
			// For now, domain exclusions match the SNI or query_name if the flow
			// has been tagged by TLS/DNS decoders — this will be enhanced when
			// TLS interception is added.
			continue
		}
	}
	return false
}

func (e *Engine) enforceDPIEvents(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event) (verdict.Verdict, bool) {
	if e == nil || state == nil || pkt == nil || len(evs) == 0 || !strings.EqualFold(e.dpiMode, "enforce") {
		return verdict.Verdict{}, false
	}
	snap := e.ruleSnap.Load()
	if snap == nil {
		return verdict.Verdict{}, false
	}
	srcZone, dstZone := resolveZonesForFlow(snap, state.Key.SrcIP, state.Key.DstIP)
	for _, ev := range evs {
		ctx, ok := evalContextFromDPIEvent(snap, state, pkt, ev, srcZone, dstZone)
		if !ok {
			continue
		}
		v := e.EvaluateVerdict(ctx)
		if v.Action == verdict.AllowContinue {
			continue
		}
		if v.Action == verdict.DenyDrop {
			v.Action = verdict.BlockFlowTemp
			if v.TTL <= 0 {
				v.TTL = dpiEnforceBlockTTL
			}
		}
		if err := e.ApplyVerdict(context.Background(), v, ctx); err != nil {
			continue
		}
		return v, true
	}
	return verdict.Verdict{}, false
}

func evalContextFromDPIEvent(_ *rules.Snapshot, state *flow.State, pkt *dpi.ParsedPacket, ev dpi.Event, srcZone, dstZone string) (rules.EvalContext, bool) {
	if state == nil || pkt == nil || !isRuleEvaluableICSEvent(ev.Proto) {
		return rules.EvalContext{}, false
	}
	service := servicePort(state, pkt)
	ctx := rules.EvalContext{
		SrcZone: srcZone,
		DstZone: dstZone,
		SrcIP:   state.Key.SrcIP,
		DstIP:   state.Key.DstIP,
		Proto:   strings.ToLower(pkt.Proto),
		Port:    strconv.Itoa(int(service)),
		ICS: &rules.ICSContext{
			Protocol:  strings.ToLower(ev.Proto),
			Address:   attrString(ev.Attributes, "address"),
			ReadOnly:  !attrBool(ev.Attributes, "is_write"),
			WriteOnly: attrBool(ev.Attributes, "is_write"),
			Direction: eventDirection(ev.Kind),
		},
	}
	if fc, ok := attrUint8(ev.Attributes, "function_code"); ok {
		ctx.ICS.FunctionCode = fc
	}
	if unitID, ok := attrUint8(ev.Attributes, "unit_id"); ok {
		unit := unitID
		ctx.ICS.UnitID = &unit
	}
	if objectClass, ok := attrUint16(ev.Attributes, "object_class"); ok {
		ctx.ICS.ObjectClass = objectClass
	}
	return ctx, true
}

func resolveZonesForFlow(snap *rules.Snapshot, srcIP, dstIP net.IP) (string, string) {
	if snap == nil || len(snap.ZoneIfaces) == 0 {
		return "", ""
	}
	type zoneNets struct {
		name string
		nets []*net.IPNet
	}
	var zones []zoneNets
	for zone, ifaces := range snap.ZoneIfaces {
		zn := zoneNets{name: zone}
		for _, ifaceName := range ifaces {
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					zn.nets = append(zn.nets, v)
				case *net.IPAddr:
					bits := 32
					if v.IP.To4() == nil {
						bits = 128
					}
					zn.nets = append(zn.nets, &net.IPNet{IP: v.IP, Mask: net.CIDRMask(bits, bits)})
				}
			}
		}
		if len(zn.nets) > 0 {
			zones = append(zones, zn)
		}
	}
	zoneForIP := func(ip net.IP) string {
		if ip == nil {
			return ""
		}
		for _, zone := range zones {
			for _, network := range zone.nets {
				if network.Contains(ip) {
					return zone.name
				}
			}
		}
		return ""
	}
	return zoneForIP(srcIP), zoneForIP(dstIP)
}

func isRuleEvaluableICSEvent(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "modbus", "dnp3", "cip", "s7comm", "mms", "bacnet", "opcua":
		return true
	default:
		return false
	}
}

func eventDirection(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "response", "exception":
		return "response"
	default:
		return "request"
	}
}

func attrBool(attrs map[string]any, key string) bool {
	if attrs == nil {
		return false
	}
	switch v := attrs[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}

func attrUint8(attrs map[string]any, key string) (uint8, bool) {
	if attrs == nil {
		return 0, false
	}
	switch v := attrs[key].(type) {
	case uint8:
		return v, true
	case uint16:
		if v <= 255 {
			return uint8(v), true
		}
	case int:
		if v >= 0 && v <= 255 {
			return uint8(v), true
		}
	case int64:
		if v >= 0 && v <= 255 {
			return uint8(v), true
		}
	case float64:
		if v >= 0 && v <= 255 {
			return uint8(v), true
		}
	}
	return 0, false
}

func attrUint16(attrs map[string]any, key string) (uint16, bool) {
	if attrs == nil {
		return 0, false
	}
	switch v := attrs[key].(type) {
	case uint16:
		return v, true
	case uint8:
		return uint16(v), true
	case int:
		if v >= 0 && v <= 65535 {
			return uint16(v), true
		}
	case int64:
		if v >= 0 && v <= 65535 {
			return uint16(v), true
		}
	case float64:
		if v >= 0 && v <= 65535 {
			return uint16(v), true
		}
	}
	return 0, false
}

func attrString(attrs map[string]any, key string) string {
	if attrs == nil {
		return ""
	}
	switch v := attrs[key].(type) {
	case string:
		return v
	case uint8:
		return strconv.FormatUint(uint64(v), 10)
	case uint16:
		return strconv.FormatUint(uint64(v), 10)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	default:
		return ""
	}
}

func servicePort(state *flow.State, pkt *dpi.ParsedPacket) uint16 {
	if state != nil && state.Key.Dir == flow.DirReverse {
		return pkt.SrcPort
	}
	return pkt.DstPort
}

func parsePortRange(s string) (uint16, uint16, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}
		if !strings.Contains(s, "-") {
			v, err := strconv.Atoi(s) // nosemgrep: trailofbits.go.string-to-int-signedness-cast.string-to-int-signedness-cast -- bounded to 0..65535 below before conversion.
			if err != nil || v < 0 || v > 65535 {
				return 0, 0, false
			}
			u := uint16(v)
			return u, u, true
		}
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
		lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0])) // nosemgrep: trailofbits.go.string-to-int-signedness-cast.string-to-int-signedness-cast -- bounded to 0..65535 below before conversion.
		hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1])) // nosemgrep: trailofbits.go.string-to-int-signedness-cast.string-to-int-signedness-cast -- bounded to 0..65535 below before conversion.
		if err1 != nil || err2 != nil || lo < 0 || hi < 0 || lo > 65535 || hi > 65535 {
			return 0, 0, false
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		return uint16(lo), uint16(hi), true
	}
