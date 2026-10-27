// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"log/slog"
	"net/netip"
	"time"

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
	if state.Key.Dir == flow.DirForward {
		return state
	}
	e.flowMu.Lock()
	client := e.flows[state.Key.Reversed().Hash()]
	e.flowMu.Unlock()
	return client
}

// observeDomainExclusions runs before selective DPI, independently of decoder
// event toggles. DNS can still be learned from a flow already excluded from DPI.
// IEC104 uses its envelope path and is never exempted by a domain association.
func (e *Engine) observeDomainExclusions(state *flow.State, pkt *dpi.ParsedPacket) {
	d := e.domains
	if d == nil || state == nil || pkt == nil {
		return
	}
	if isIECFlow(state) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if d.lastPrune.IsZero() || now.Sub(d.lastPrune) >= 30*time.Second {
		e.pruneDomainDecisionsLocked()
		d.lastPrune = now
	}
	if pkt.TCPSyn && state.Key.Dir == flow.DirForward {
		delete(d.decisions, state)
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
	if state.Key.Dir != flow.DirForward {
		return
	}
	if _, decided := d.decisions[state]; decided {
		return
	}
	name, reason := "", "dns"
	if state.Key.Proto == 6 {
		name = itdpi.ClientHelloSNI(pkt.Payload)
	}
	if name != "" {
		reason = "sni"
	} else if ip, ok := netip.AddrFromSlice(state.Key.ServerIP()); ok {
		name = d.lookup(ip)
	}
	rule := e.domainRule(name)
	d.decisions[state] = rule != ""
	if rule != "" {
		e.countDomainExclusion(rule)
		e.recordDomainCounter("dpi_exclusion_" + reason)
		slog.Debug("DPI domain exclusion matched", "rule", rule, "reason", reason, "name", name, "flow", state.Key.Hash())
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
	for state := range e.domains.decisions {
		if e.flows[state.Key.Hash()] != state {
			delete(e.domains.decisions, state)
		}
	}
}

// Reuse protocol event counters so the existing DPI statistics API exposes
// reason-level flow hits and capacity evictions without another telemetry API.
func (e *Engine) recordDomainCounter(reason string) {
	e.recordProtoStats([]dpi.Event{{Proto: reason, Kind: "counter", Timestamp: e.domains.now()}})
}
