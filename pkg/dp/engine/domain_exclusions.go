// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"log/slog"
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
)

func (e *Engine) domainRule(name string) string {
	for _, x := range e.dpiExclusions {
		if x.Type == "domain" && domainMatches(x.Value, name) {
			return x.Value
		}
	}
	return ""
}

func (e *Engine) domainClientState(state *flow.State) *flow.State {
	direction := state.ServiceKey().Dir
	if direction == flow.DirForward {
		return state
	}
	return e.peerFlow(state)
}

// observeDomainExclusions runs before selective DPI, independently of decoder
// event toggles. DNS can still be learned from a flow already excluded from DPI.
// IEC104 uses its envelope path and is never exempted by a domain association.
func (e *Engine) observeDomainExclusions(state *flow.State, pkt *dpi.ParsedPacket) {
	e.observeDomain(state, pkt, false)
}

func (e *Engine) observeDomain(state *flow.State, pkt *dpi.ParsedPacket, discovery bool) {
	d := e.domains
	if d == nil || state == nil || pkt == nil {
		return
	}
	if isIECFlow(state) && !discovery {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	decisions := d.decisions
	if discovery {
		decisions = d.discoveryDecisions
	}
	now := d.now()
	if d.lastPrune.IsZero() || now.Sub(d.lastPrune) >= 30*time.Second {
		e.pruneDomainDecisionsLocked()
		d.lastPrune = now
	}
	if pkt.TCPSyn && state.ServiceKey().Dir == flow.DirForward {
		delete(decisions, state)
	}
	if len(pkt.Payload) == 0 {
		return
	}
	if (state.Key.Proto == 6 || state.Key.Proto == 17) && pkt.SrcPort == 53 {
		before := d.evictions
		for _, a := range itdpi.DNSAnswers(pkt.Payload, state.Key.Proto == 6) {
			if e.domainRule(a.Name) != "" {
				d.add(a.IP, a.Name, a.TTL)
			}
		}
		for i := before; i < d.evictions; i++ {
			e.recordDomainCounter("dpi_domain_cache_eviction")
		}
	}
	if state.ServiceKey().Dir != flow.DirForward {
		return
	}
	if _, decided := decisions[state]; decided {
		return
	}
	name, reason := "", "dns"
	if state.Key.Proto == 6 {
		name = itdpi.ClientHelloSNI(pkt.Payload)
	}
	if name != "" {
		reason = "sni"
	} else if ip, ok := netip.AddrFromSlice(state.ServiceKey().ServerIP()); ok {
		name = d.lookup(ip)
	}
	rule := e.domainRule(name)
	decisions[state] = rule != ""
	if rule != "" {
		e.countDomainExclusion(rule)
		e.recordDomainCounter("dpi_exclusion_" + reason)
		slog.Debug("DPI domain exclusion matched", "rule", rule, "reason", reason, "name", name, "flow", state.ID())
	}
}

func (e *Engine) domainExcluded(state *flow.State) bool {
	if e.domains == nil || state == nil {
		return false
	}
	if isIECFlow(state) {
		return false
	}
	client := e.domainClientState(state)
	d := e.domains
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.decisions[client]
}

// pruneDomainDecisionsLocked retains decisions for every live flow, without a
// capacity eviction ever reversing a decision. The flow tracker owns lifetime;
// remove entries for swept flows or superseded tuple incarnations on traffic.
// Requires domains.mu; flow tracking never acquires that lock under flowMu.
func (e *Engine) pruneDomainDecisionsLocked() {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	for state := range e.domains.discoveryDecisions {
		if e.flows[state.Key.MapKey()] != state {
			delete(e.domains.discoveryDecisions, state)
		}
	}
	for state := range e.domains.decisions {
		if e.flows[state.Key.MapKey()] != state {
			delete(e.domains.decisions, state)
		}
	}
}

// Reuse protocol event counters so the existing DPI statistics API exposes
// reason-level flow hits and capacity evictions without another telemetry API.
func (e *Engine) recordDomainCounter(reason string) {
	e.recordProtoStats([]dpi.Event{{Proto: reason, Kind: "counter", Timestamp: e.domains.now()}})
}

// Discovery has its own domain decision, including TCP/2404. It never changes
// the envelope owner's historical exemption.
func (e *Engine) discoveryDomainExcluded(state *flow.State, pkt capture.Packet) bool {
	if e.domains == nil {
		return false
	}
	parsed := observationPacket(state)
	parsed.Payload, parsed.TCPSyn = pkt.Payload, pkt.TCP.Flags&capture.TCPFlagSYN != 0
	e.observeDomain(state, parsed, true)
	client := e.domainClientState(state)
	e.domains.mu.Lock()
	defer e.domains.mu.Unlock()
	return e.domains.discoveryDecisions[client]
}
