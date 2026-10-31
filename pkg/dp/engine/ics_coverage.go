// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"sync/atomic"

	"github.com/tonylturner/containd/pkg/dp/coverage"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// coverageSettings are the static coverage inputs of an engine
// configuration. The DPI mock inspects even with the master switch off.
func coverageSettings(cfg Config) coverage.Settings {
	s := coverage.Settings{
		Enforcement:  cfg.Enforce.Enabled,
		QueueID:      cfg.NFQueueGroup,
		DPIEnabled:   cfg.DPIEnabled || cfg.InspectAll,
		DPIMode:      cfg.DPIMode,
		ICSProtocols: cfg.DPIICSProtocols,
	}
	for _, x := range cfg.DPIExclusions {
		s.Exclusions = append(s.Exclusions, coverage.Exclusion{Value: x.Value, Type: x.Type})
	}
	return s
}

// ICSCoverage reports the coverage of the applied snapshot's ICS rules
// under the running settings, with the runtime overlay. A failed apply
// leaves the previous snapshot, and so its coverage, in place.
func (e *Engine) ICSCoverage() []coverage.Rule {
	if e == nil {
		return nil
	}
	return e.coverageOf(e.ruleSnap.Load())
}

// coverageOf evaluates snap statically, then adds what only the running
// engine knows: whether it holds the configured queue (a Runtime reason), and
// how many flows each exclusion has exempted since the last apply. Matches
// only annotate the static exclusion reasons: a count is per exclusion, not
// per rule, so it never adds a reason to a rule whose scope the exclusion
// does not meet.
func (e *Engine) coverageOf(snap *rules.Snapshot) []coverage.Rule {
	e.flowMu.Lock()
	s, hits := e.coverage, e.exclusionHits
	e.flowMu.Unlock()
	out := coverage.Evaluate(snap, s)
	if len(out) == 0 {
		return nil
	}
	bound := s.QueueID == 0 || e.gate.sampleOpen(int(s.QueueID))
	for i := range out {
		r := &out[i]
		for j := range r.Reasons {
			if c := r.Reasons[j].Code; c == coverage.ExclusionOverlap || c == coverage.DomainExclusion {
				r.Reasons[j].Matches = hits.get(r.Reasons[j].Value)
			}
		}
		if r.Mode == "enforce" && s.Enforcement && !bound {
			r.Lower(coverage.Reason{Code: coverage.QueueUnavailable, Runtime: true,
				Message: "this engine does not hold the configured NFQUEUE, so the kernel drops the rule's traffic instead of inspecting it"})
		}
	}
	return out
}

// exclusionHits counts, per DPI exclusion value, the flows the exclusion
// exempted from inspection. The map is fixed per configuration; nil means
// no exclusions.
type exclusionHits struct {
	byValue map[string]*atomic.Uint64
}

func newExclusionHits(xs []DPIExclusion) *exclusionHits {
	if len(xs) == 0 {
		return nil
	}
	h := &exclusionHits{byValue: make(map[string]*atomic.Uint64, len(xs))}
	for _, x := range xs {
		h.byValue[x.Value] = new(atomic.Uint64)
	}
	return h
}

func (h *exclusionHits) add(value string) {
	if h == nil {
		return
	}
	if c := h.byValue[value]; c != nil {
		c.Add(1)
	}
}

func (h *exclusionHits) get(value string) uint64 {
	if h == nil {
		return 0
	}
	if c := h.byValue[value]; c != nil {
		return c.Load()
	}
	return 0
}

func (h *exclusionHits) reset() {
	if h == nil {
		return
	}
	for _, c := range h.byValue {
		c.Store(0)
	}
}

// resetExclusionHits starts the match counts of a newly applied rule set.
func (e *Engine) resetExclusionHits() {
	e.flowMu.Lock()
	hits := e.exclusionHits
	e.flowMu.Unlock()
	hits.reset()
}

// countAddressExclusionLocked counts a new connection that an IP or CIDR
// exclusion exempts from inspection. IEC 104 sessions are inspected
// regardless, and nothing is exempted while DPI is off. Requires flowMu.
func (e *Engine) countAddressExclusionLocked(state *flow.State) {
	if e.exclusionHits == nil || (!e.dpiEnabled && !e.inspectAll) || isIECFlow(state) {
		return
	}
	if v := e.addressExclusion(state); v != "" {
		e.exclusionHits.add(v)
	}
}

// countDomainExclusion counts a connection that a domain exclusion exempts.
func (e *Engine) countDomainExclusion(value string) {
	if e.dpiEnabled || e.inspectAll {
		e.exclusionHits.add(value)
	}
}

// addressExclusion returns the first IP or CIDR exclusion that matches
// either endpoint of the flow, or "".
func (e *Engine) addressExclusion(state *flow.State) string {
	key := state.ServiceKey()
	for _, excl := range e.dpiExclusions {
		switch excl.Type {
		case "ip":
			ip := net.ParseIP(excl.Value)
			if ip != nil && (key.SrcIP.Equal(ip) || key.DstIP.Equal(ip)) {
				return excl.Value
			}
		case "cidr":
			_, cidr, err := net.ParseCIDR(excl.Value)
			if err == nil && (cidr.Contains(key.SrcIP) || cidr.Contains(key.DstIP)) {
				return excl.Value
			}
		}
	}
	return ""
}

// isIECFlow reports a TCP flow on the IEC 104 port, which domain and
// address exclusions never exempt.
func isIECFlow(state *flow.State) bool {
	key := state.ServiceKey()
	return key.Proto == 6 && (key.SrcPort == iec104Port || key.DstPort == iec104Port)
}
