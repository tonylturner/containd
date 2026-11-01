// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
)

// InspectionSnapshot keeps offline imports and watch fingerprints bound to the
// same immutable decoder registry and policy inputs during reconfiguration.
type InspectionSnapshot struct {
	Decoders []dpi.Decoder
	Parsing  map[string]string
	Rules    *rules.Snapshot
	Token    InspectionToken
}

// InspectionToken is a comparable identity for immutable installed inputs.
// It avoids serializing a policy on every forwarding event.
type InspectionToken struct {
	rules    *rules.Snapshot
	parsing  *map[string]string
	registry uint64
}

func (e *Engine) InspectionToken() InspectionToken {
	return InspectionToken{e.CurrentRules(), e.icsParsing.Load(), e.inspectionRegistry.Load()}
}

func (e *Engine) InspectionSnapshot() InspectionSnapshot {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	inputs := InspectionSnapshot{Rules: e.CurrentRules(), Parsing: map[string]string{}, Token: e.InspectionToken()}
	if e.dpiMgr != nil {
		inputs.Decoders = append([]dpi.Decoder{}, e.dpiMgr.Decoders()...)
	}
	var modes map[string]string
	if value := e.icsParsing.Load(); value != nil {
		modes = *value
	}
	for _, protocol := range []string{"modbus", "dnp3", "iec104", "cip"} {
		inputs.Parsing[protocol] = string(ics.EffectiveParsing(modes, protocol))
	}
	return inputs
}

type learnWatchHook struct {
	offer func(*flow.State, []dpi.Event)
}

// SetLearnWatchHook installs the explicit, nonblocking evidence collector.
// A nil hook disables collection independently of every enforcement mode.
func (e *Engine) SetLearnWatchHook(offer func(*flow.State, []dpi.Event)) {
	if offer == nil {
		e.learnWatch.Store(nil)
	} else {
		e.learnWatch.Store(&learnWatchHook{offer: offer})
	}
}
func (e *Engine) recordLearnEvents(state *flow.State, evs []dpi.Event) {
	if hook := e.learnWatch.Load(); hook != nil && state != nil {
		e.flowMu.Lock()
		snapshot := *state
		var lossPacket capture.Packet
		knownLoss := false
		if r := e.transport; r != nil {
			r.admissionMu.Lock()
			if c := e.transportCoverage[state].root(); c != nil && c.lost {
				lossPacket, knownLoss = c.packet, true
			}
			r.admissionMu.Unlock()
		}
		e.flowMu.Unlock()
		// A watch may start with a preexisting loss notice still pending.
		// Never admit a parent from that marked connection as clean.
		if knownLoss {
			e.recordLearnCaptureLoss(lossPacket, snapshot.Connection.Load())
		}
		hook.offer(&snapshot, evs)
	}
}

func (e *Engine) recordLearnOutcome(events []dpi.Event) {
	if hook := e.learnWatch.Load(); hook != nil {
		hook.offer(nil, events)
	}
}

// SetLearnLossHook fences synchronous loss admissions independently of the
// semantic queue. Disabling waits for every already-entered callback to finish.
// The callback must be nonblocking and must not reenter this hook setter.
func (e *Engine) SetLearnLossHook(offer func(evidence.CollectionLoss)) {
	// Admission records coverage before invoking the hook. Fence that whole
	// critical section, not just callbacks that already acquired learnLossMu.
	if r := e.transport; r != nil {
		r.admissionMu.Lock()
		defer r.admissionMu.Unlock()
	}
	e.learnLossMu.Lock()
	defer e.learnLossMu.Unlock()
	e.learnLoss = offer
}

func (e *Engine) recordLearnCaptureLoss(pkt capture.Packet, connection *flow.Connection) {
	loss := learn.CaptureLoss(pkt, "capture_loss")
	if connection != nil && connection.Key != "" {
		loss.ConnectionID = connection.Key
	}
	e.learnLossMu.RLock()
	defer e.learnLossMu.RUnlock()
	if e.learnLoss != nil {
		e.learnLoss(loss)
	}
}

// Full ports permit an admission-index identity lookup without network I/O.
// Partial ports retain host-pair scope; certification checks every retained
// verified alias, including mappings on connections with no retained reply.
func (e *Engine) recordLearnPacketLoss(pkt capture.Packet) {
	var connection *flow.Connection
	if r := e.transport; r != nil {
		r.admissionMu.Lock()
		defer r.admissionMu.Unlock()
		if pkt.Invalid != capture.InvalidIPHeader && (pkt.PortsValid || pkt.TCP.Valid) {
			if entry := r.indexed[packetKey(pkt).Tuple()]; entry != nil && !entry.connection.Closed().Load() {
				connection = entry.connection
			}
		}
	}
	e.recordLearnCaptureLoss(pkt, connection)
}
