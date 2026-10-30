// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// InspectionSnapshot keeps offline imports and watch fingerprints bound to the
// same immutable decoder registry and policy inputs during reconfiguration.
type InspectionSnapshot struct {
	Decoders []dpi.Decoder
	Parsing  map[string]string
	Rules    *rules.Snapshot
}

func (e *Engine) InspectionSnapshot() InspectionSnapshot {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	inputs := InspectionSnapshot{Rules: e.CurrentRules(), Parsing: map[string]string{}}
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
		e.flowMu.Unlock()
		hook.offer(&snapshot, evs)
	}
}

func (e *Engine) recordLearnOutcome(events []dpi.Event) {
	if hook := e.learnWatch.Load(); hook != nil {
		hook.offer(nil, events)
	}
}
