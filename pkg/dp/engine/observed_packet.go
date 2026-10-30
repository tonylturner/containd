// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// enforcingPacketScope is decided before decoding, in post-DNAT service
// coordinates. Identity, schedules and payload predicates do not narrow an
// inspection scope: a failed predicate must still fail closed inside it.
func (e *Engine) enforcingPacketScope(pkt capture.Packet, state *flow.State) bool {
	p := e.ruleSnap.current.Load()
	if p == nil || p.snapshot == nil {
		return false
	}
	key := state.ServiceKey()
	// A forged reverse SYN must not change a denied incarnation's scope.
	// Retain its verified service coordinates, but still resolve the scope
	// against the currently installed policy (which may now be monitor-only).
	e.flowMu.Lock()
	if denied := e.deniedTCP[tcpTupleKey(state.Key)]; denied != nil {
		key = denied.service
	}
	e.flowMu.Unlock()
	scopeState := &flow.State{Key: key}
	ctx := rules.EvalContext{SrcIP: key.OpenerIP(), DstIP: key.ServerIP()}
	ctx.SrcZone, ctx.DstZone = e.zones.resolve(p.snapshot, ctx.SrcIP, ctx.DstIP)
	parsed := &dpi.ParsedPacket{Proto: pkt.Transport, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort}
	for i, entry := range p.snapshot.Firewall {
		if entry.ICS.Protocol != "" && rules.EffectiveMode(entry.ICS.Mode, p.snapshot.DPIMode) == "enforce" &&
			shouldInspectFirewallEntry(entry, scopeState, parsed) && p.evaluator.AddressScopeMatch(i, ctx) {
			return true
		}
	}
	return false
}

func observedDecision(pkt capture.Packet) capture.Decision {
	return capture.Decision{Action: capture.Repeat, Mark: pkt.Mark & ^enforce.QueueMarkMask | enforce.ObservedMark, Reason: "ics_observed"}
}
