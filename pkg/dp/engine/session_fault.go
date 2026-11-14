// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func (t *sessionTable) inspectSession(state *flow.State, parsed *dpi.ParsedPacket) (result dpi.InspectResult, fault error) {
	defer func() {
		if r := recover(); r != nil {
			fault = packetPanic(r)
			result = dpi.InspectResult{Framed: true, Err: &dpi.StreamError{Kind: dpi.StreamDecoderPanic, Proto: sessionProtocol(state)}}
		}
	}()
	return t.dpi.Inspect(state, parsed), nil
}

// Stream faults report the scope that required inspection, not an event-derived
// authorization decision. They never enter the legacy denial registry.
func (t *sessionTable) streamFailureLocked(s *trackedSession, res *sessionResult, err error) {
	if s.mode != "enforce" || sessionProtocol(s.flow) == iecProtocol {
		return
	}
	if compiled := t.ruleOwner.current.Load(); compiled != nil {
		res.streamScope = t.genericScopeLocked(s, compiled)
	}
	res.streamErr = err
	res.decision.Reason = reasonStreamFailClosed
}
