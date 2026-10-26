// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
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

// enforceDPIEvents evaluates decoded ICS events against the firewall rules
// and returns the first enforced denial with its context. It performs no
// I/O: the caller drops the packet and installs the dynamic block after the
// verdict. Logging of matched Log rules still happens in
// EvaluateVerdictMatch for learn and enforce modes alike.
func (e *Engine) enforceDPIEvents(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event) (verdict.Verdict, rules.EvalContext, bool) {
	if e == nil || state == nil || pkt == nil || len(evs) == 0 {
		return verdict.Verdict{}, rules.EvalContext{}, false
	}
	snap := e.ruleSnap.Load()
	if snap == nil {
		return verdict.Verdict{}, rules.EvalContext{}, false
	}
	// Policy describes connections from the opener to the server, so a
	// reply is evaluated with the connection's orientation. The default
	// action governs requests only: a reply is enforced only when a rule
	// matches it. NFQUEUE mode behaves the same, because replies take the
	// established conntrack path there and are never queued.
	srcZone, dstZone := resolveZonesForFlow(snap, state.Key.OpenerIP(), state.Key.ServerIP())
	applyDefault := !isReply(state)
	for _, ev := range evs {
		ctx, ok := evalContextFromDPIEvent(snap, state, pkt, ev, srcZone, dstZone)
		if !ok {
			continue
		}
		v, matched := e.evaluateVerdictMatch(ctx, applyDefault)
		if v.Action == verdict.AllowContinue {
			continue
		}
		if e.effectiveMode(matched) != "enforce" {
			// Logged by EvaluateVerdictMatch ("would have been blocked")
			// but not applied: the rule is in learn mode.
			continue
		}
		if v.Action == verdict.DenyDrop {
			v.Action = verdict.BlockFlowTemp
			if v.TTL <= 0 {
				v.TTL = dpiEnforceBlockTTL
			}
		}
		return v, ctx, true
	}
	return verdict.Verdict{}, rules.EvalContext{}, false
}

func evalContextFromDPIEvent(_ *rules.Snapshot, state *flow.State, pkt *dpi.ParsedPacket, ev dpi.Event, srcZone, dstZone string) (rules.EvalContext, bool) {
	if state == nil || pkt == nil || !isRuleEvaluableICSEvent(ev.Proto) || isStreamErrorEvent(ev) {
		return rules.EvalContext{}, false
	}
	service := servicePort(state, pkt)
	// Read/write class comes only from a present is_write: an event that
	// does not say it is a write is not thereby read-only.
	isWrite, hasWrite := eventfields.Bool(ev.Attributes, eventfields.KeyIsWrite)
	ctx := rules.EvalContext{
		SrcZone: srcZone,
		DstZone: dstZone,
		SrcIP:   state.Key.OpenerIP(),
		DstIP:   state.Key.ServerIP(),
		Proto:   strings.ToLower(pkt.Proto),
		Port:    strconv.Itoa(int(service)),
		ICS: &rules.ICSContext{
			Protocol:  strings.ToLower(ev.Proto),
			Address:   attrString(ev.Attributes, "address"),
			ReadOnly:  hasWrite && !isWrite,
			WriteOnly: hasWrite && isWrite,
			Direction: messageDirection(state, ev.Kind),
		},
	}
	if fc, ok := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode); ok {
		ctx.ICS.FunctionCode = fc
	}
	if unitID, ok := eventfields.Uint8(ev.Attributes, eventfields.KeyUnitID); ok {
		ctx.ICS.UnitID = &unitID
	}
	if objectClass, ok := eventfields.Uint16(ev.Attributes, "object_class"); ok {
		ctx.ICS.ObjectClass = objectClass
	}
	return ctx, true
}

type zoneResolver func(*rules.Snapshot, net.IP, net.IP) (string, string)

func resolveZonesForFlow(snap *rules.Snapshot, srcIP, dstIP net.IP) (string, string) {
	return resolveZonesWithAddrs(snap, srcIP, dstIP, interfaceAddrs)
}

// interfaceAddrs keeps OS interface lookup in the engine's network namespace.
func interfaceAddrs(name string) ([]net.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return iface.Addrs()
}

func resolveZonesWithAddrs(snap *rules.Snapshot, srcIP, dstIP net.IP, addrsFor func(string) ([]net.Addr, error)) (string, string) {
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
			addrs, err := addrsFor(ifaceName)
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

// isStreamErrorEvent reports a malformed or unsupported event. Such events
// are evidence only: on US protocols the packet passes, so they
// never reach rule evaluation, where a missing function code would read as
// FC 0.
func isStreamErrorEvent(ev dpi.Event) bool {
	return ev.Kind == "malformed" || ev.Kind == "unsupported"
}

// isReply is deliberately limited to the US path; IEC envelopes evaluate
// both directions through EvaluateIEC104 and deny unmatched replies.
func isReply(state *flow.State) bool { return state.Key.Dir == flow.DirReverse }

func messageDirection(state *flow.State, kind string) string {
	if isReply(state) {
		return "response"
	}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "response", "exception":
		return "response"
	default:
		return "request"
	}
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

// servicePort returns the server port of the packet's connection: the
// destination port when the sender opened the connection, the source port
// on its replies.
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
