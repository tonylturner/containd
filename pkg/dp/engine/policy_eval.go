// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
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

// isExcluded checks whether either endpoint of a flow matches a DPI
// exclusion. Domain exclusions were decided by the pre-selection observer.
func (e *Engine) isExcluded(state *flow.State) bool {
	return e.addressExclusion(state) != "" || e.domainExcluded(state)
}

// enforceDPIEvents evaluates decoded ICS events against the firewall rules
// and returns the first enforced denial with its context. The caller
// drops the packet and resets the session after the verdict. Conformance
// alerts and shadow/deny decisions use the existing event store. streamDenied
// reports a pending fail-closed drop so its conformance alert names the actual
// packet outcome. Matched Log rules still log in both learn and enforce modes.
func (e *Engine) enforceDPIEvents(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event, streamDenied bool) (verdict.Verdict, rules.EvalContext, bool) {
	if e == nil || state == nil || pkt == nil || len(evs) == 0 {
		return verdict.Verdict{}, rules.EvalContext{}, false
	}
	snap := e.ruleSnap.Load()
	if snap == nil {
		for _, ev := range evs {
			if isRuleEvaluableICSEvent(ev.Proto) {
				e.recordConformanceAlert(state, pkt, ev, "passed")
			}
		}
		return verdict.Verdict{}, rules.EvalContext{}, false
	}
	// Policy describes connections from the opener to the server, so a
	// reply is evaluated with the connection's orientation. The default
	// action governs requests only: a reply is enforced only when a rule
	// matches it. NFQUEUE mode behaves the same, because replies take the
	// established conntrack path there and are never queued.
	key := state.ServiceKey()
	srcZone, dstZone := e.zones.resolve(snap, key.OpenerIP(), key.ServerIP())
	applyDefault := !isReply(state)
	// First arbitrate decoded denials across the whole packet. A later decoded
	// deny keeps its reason even when an earlier event has strict findings.
	type evaluated struct {
		ev      dpi.Event
		ctx     rules.EvalContext
		v       verdict.Verdict
		matched *rules.Entry
		scope   *rules.Entry
		strict  bool
	}
	var modes map[string]string
	if p := e.icsParsing.Load(); p != nil {
		modes = *p
	}
	var results []evaluated
	var denied verdict.Verdict
	var deniedCtx rules.EvalContext
	for _, ev := range evs {
		contexts := evalContextsFromDPIEvent(snap, state, pkt, ev, srcZone, dstZone)
		if len(contexts) == 0 {
			continue
		}
		r := evaluated{ev: ev, ctx: contexts[0]}
		findings := hasInspectionFindings(ev)
		if findings {
			r.scope = e.conformanceScope(state, pkt, ev.Proto)
			r.strict = r.scope != nil && ics.EffectiveParsing(modes, strings.ToLower(ev.Proto)) == ics.Strict
		}
		for i, ctx := range contexts {
			var v verdict.Verdict
			var matched *rules.Entry
			if !denied.Denies() {
				v, matched = e.evaluateVerdictMatch(ctx, applyDefault, state)
			}
			// Strict replaces defaults, but never a decoded rule denial.
			if r.strict && matched == nil {
				v = verdict.Verdict{Action: verdict.AllowContinue}
			}
			if i == 0 || (!r.v.Denies() && v.Denies()) {
				r.ctx, r.v, r.matched = ctx, v, matched
			}
			if v.Denies() && e.effectiveMode(matched) == "enforce" && !denied.Denies() {
				denied, deniedCtx = v, ctx
			}
		}
		// Record findings once per event, not once per object header.
		if findings {
			results = append(results, r)
		}
	}

	// Strict nonconformance overrides ALLOW, not a decoded denial. Learn
	// scopes produce shadow decisions only, even when the global mode enforces.
	for _, r := range results {
		if !r.strict || denied.Denies() {
			continue
		}
		if e.effectiveMode(r.scope) == "enforce" {
			denied = verdict.Verdict{Action: verdict.DenyDrop, Reason: reasonNonconformant}
			if r.v.Denies() {
				denied = r.v
			}
			deniedCtx = r.ctx
		}
	}
	for _, r := range results {
		action := "passed"
		scope, strict := r.scope, r.strict
		mode := e.effectiveMode(scope)
		if denied.Denies() || streamDenied {
			action = "dropped and reset"
		} else if strict || r.v.Denies() {
			action = "would drop"
		}
		if r.v.Denies() {
			reason := "rule"
			if r.matched == nil {
				reason = "default"
			}
			decision := decisionWouldDrop
			if e.effectiveMode(r.matched) == "enforce" {
				decision = decisionDeny
			}
			decisionMode := e.effectiveMode(r.matched)
			if strict && mode == "enforce" {
				decision, decisionMode = decisionDeny, mode
			}
			e.recordConformanceDecision(state, pkt, r.ev, r.matched, decisionMode, decision, reason)
		} else if strict && (!denied.Denies() || denied.Reason == reasonNonconformant) {
			decision := decisionWouldDrop
			if mode == "enforce" {
				decision = decisionDeny
			}
			e.recordConformanceDecision(state, pkt, r.ev, scope, mode, decision, reasonNonconformant)
		}
		e.recordConformanceAlert(state, pkt, r.ev, action)
	}
	return denied, deniedCtx, denied.Denies()
}

type zoneResolver func(*rules.Snapshot, net.IP, net.IP) (string, string)

// interfaceAddrs keeps OS interface lookup in the engine's network namespace.
func interfaceAddrs(name string) ([]net.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return iface.Addrs()
}

// zoneIndex maps addresses to the zone whose interface networks hold them.
type zoneIndex []zoneNets

type zoneNets struct {
	name string
	nets []*net.IPNet
}

// newZoneIndex reads the networks of snap's zone interfaces once, for any
// number of lookups.
func newZoneIndex(snap *rules.Snapshot, addrsFor func(string) ([]net.Addr, error)) zoneIndex {
	if snap == nil || len(snap.ZoneIfaces) == 0 {
		return nil
	}
	var zones zoneIndex
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
	return zones
}

// zoneFor returns the zone of ip, or "".
func (z zoneIndex) zoneFor(ip net.IP) string {
	if ip == nil {
		return ""
	}
	for _, zone := range z {
		for _, network := range zone.nets {
			if network.Contains(ip) {
				return zone.name
			}
		}
	}
	return ""
}

func isRuleEvaluableICSEvent(proto string) bool {
	proto = strings.ToLower(strings.TrimSpace(proto))
	// IEC104 is evaluated through its APDU envelope path, not generic events.
	return proto != "iec104" && ics.Supported(proto)
}

// isStreamErrorEvent reports a malformed or unsupported event. Such events
// never reach rule evaluation, where a missing function code would read as
// FC 0. The event alone does not block: a packet fails closed only when the
// decoder also returns a stream or frame error and the flow is inline in the
// scope of an enforce ICS rule (failClosedRule, isStreamFailure).
func isStreamErrorEvent(ev dpi.Event) bool {
	return ev.Kind == "malformed" || ev.Kind == "unsupported"
}

// isReply is deliberately limited to the US path; IEC envelopes evaluate
// both directions through EvaluateIEC104 and deny unmatched replies.
func isReply(state *flow.State) bool { return state.ServiceKey().Dir == flow.DirReverse }

func messageDirection(state *flow.State) string {
	if isReply(state) {
		return "response"
	}
	return "request"
}

// servicePort returns the server port of the packet's connection: the
// destination port when the sender opened the connection, the source port
// on its replies.
func servicePort(state *flow.State, pkt *dpi.ParsedPacket) uint16 {
	if state != nil {
		key := state.ServiceKey()
		if key.Dir == flow.DirReverse {
			return key.SrcPort
		}
		return key.DstPort
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
