// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// RulesetPreviewRuntime describes the envelope decision sampled for a preview
// or why enforcement would apply nothing, not the last installed kernel state.
type RulesetPreviewRuntime struct {
	IEC104EnvelopeOpen bool   `json:"iec104EnvelopeOpen"`
	Reason             string `json:"reason"`
}

type RulesetPreview struct {
	Snapshot rules.Snapshot        `json:"snapshot"`
	Ruleset  string                `json:"ruleset,omitempty"`
	Runtime  RulesetPreviewRuntime `json:"runtime"`
}

// PreviewRuleset compiles an isolated candidate with the queue ownership sampled
// now. A subsequent bind or reconfiguration can change the eventual apply.
func (e *Engine) PreviewRuleset(snap rules.Snapshot, settings enforce.CompilerSettings) (RulesetPreview, error) {
	if err := enforce.ValidateManagementSnapshot(&snap, e.managementReservation); err != nil {
		return RulesetPreview{}, err
	}
	comp := enforce.NewCompilerWithSettings(settings, e.managementReservation)
	comp.IEC104EnvelopeOpen = e.gate.sampleOpen(comp.QueueID)
	runtime := RulesetPreviewRuntime{IEC104EnvelopeOpen: comp.IEC104EnvelopeOpen}
	switch {
	case !comp.SteersIEC104(&snap):
		runtime.Reason = "IEC 104 envelope not used by this candidate"
	case comp.IEC104EnvelopeOpen:
		runtime.Reason = "IEC 104 envelope open: candidate queue is owned by this engine"
	default:
		runtime.Reason = "IEC 104 envelope closed: candidate queue is not owned by this engine"
	}
	ruleset, err := comp.CompileFirewall(&snap)
	if err != nil {
		return RulesetPreview{}, err
	}
	return RulesetPreview{Snapshot: snap, Ruleset: ruleset, Runtime: runtime}, nil
}
