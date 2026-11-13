// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// uninspectableDecision precedes every decoder and verdict cache, including
// IEC sessions. Exclusions veto only the affected flow, not the entire rule.
// The static check also protects packets already queued across a DPI cutover.
func (e *Engine) uninspectableDecision(pkt capture.Packet, state *flow.State) (capture.Decision, bool) {
	if !pkt.Token.Inline() {
		return capture.Decision{}, false
	}
	p := e.ruleSnap.current.Load()
	if p == nil || p.snapshot == nil {
		return capture.Decision{}, false
	}
	ctx := statePolicyContext(p.snapshot, state, &e.zones)
	for i, entry := range p.snapshot.Firewall {
		if !entry.Action.Decides() || entry.ICS.Protocol == "" || rules.MonitorICS(entry, p.snapshot.DPIMode) || !p.evaluator.TransportScopeMatch(i, ctx) {
			continue
		}
		cause := rules.InspectionUnavailable(e.dpiEnabled || e.inspectAll, e.coverage.ICSProtocols, entry.ICS.Protocol)
		if cause == "" {
			if value := e.addressExclusion(state); value != "" {
				for _, x := range e.dpiExclusions {
					if x.Value == value && (x.Type == "ip" || x.Type == "cidr") {
						cause = x.Type
						if isIECFlow(state) && state.Key.Dir == flow.DirForward && state.Packets == 1 {
							e.exclusionHits.add(value)
						}
						break
					}
				}
			}
		}
		if cause == "" {
			continue
		}
		reason := "ics_uninspectable_" + cause
		e.recordPacketStats(pkt, state)
		if entry.Log {
			e.eventStore.Append(events.Event{Kind: "firewall.rule.hit", Timestamp: time.Now().UTC(), FlowID: state.ID(),
				SrcIP: pkt.SrcIP.String(), DstIP: pkt.DstIP.String(), SrcPort: pkt.SrcPort, DstPort: pkt.DstPort, Transport: pkt.Transport,
				Attributes: map[string]any{"ruleId": entry.ID, "action": string(rules.ActionDeny), "reason": reason}})
		}
		return capture.Decision{Action: capture.Drop, Reason: reason}, true
	}
	return capture.Decision{}, false
}
