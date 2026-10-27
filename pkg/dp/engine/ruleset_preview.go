// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// RulesetPreviewRuntime describes the runtime state sampled for a preview:
// the envelope decision and the scanning gate's admission the candidate would
// be compiled with, or why enforcement would apply nothing. It is not the
// last installed kernel state.
type RulesetPreviewRuntime struct {
	IEC104EnvelopeOpen bool   `json:"iec104EnvelopeOpen"`
	Reason             string `json:"reason"`
	// GateAdmit is the admission state of the scanning gate held by the
	// engine (GateAdmitName) and GateAdmitReason what it means for the
	// candidate; both are empty when nothing would be applied.
	GateAdmit       string `json:"gateAdmit,omitempty"`
	GateAdmitReason string `json:"gateAdmitReason,omitempty"`
}

type RulesetPreview struct {
	Snapshot rules.Snapshot        `json:"snapshot"`
	Ruleset  string                `json:"ruleset,omitempty"`
	Runtime  RulesetPreviewRuntime `json:"runtime"`
	// Warnings lists the rules of the candidate that match nothing (see
	// enforce.RuleWarnings); omitted when there are none.
	Warnings []enforce.RuleWarning `json:"warnings,omitempty"`
}

// GateAdmitName is the operator-facing name of a gate admission state.
func GateAdmitName(state enforce.GateAdmitState) string {
	switch state {
	case enforce.GateAdmitOpen:
		return "open"
	case enforce.GateAdmitPass:
		return "pass"
	default:
		return "refuse"
	}
}

// PreviewRuleset compiles an isolated candidate with the queue ownership and
// the gate admission sampled now and schedule time sets planned from now. A
// subsequent bind, reconfiguration or admission switch, or a later apply
// time, can change the eventual apply.
func (e *Engine) PreviewRuleset(snap rules.Snapshot, settings enforce.CompilerSettings) (RulesetPreview, error) {
	if err := enforce.ValidateManagementSnapshot(&snap, e.managementReservation); err != nil {
		return RulesetPreview{}, err
	}
	comp := enforce.NewCompilerWithSettings(settings, e.managementReservation)
	comp.EngineAPI = e.engineAPI
	comp.IEC104EnvelopeOpen = e.gate.sampleOpen(comp.QueueID)
	comp.GateAdmit = e.GateAdmit()
	comp.ScheduleFrom = e.gate.now()
	runtime := RulesetPreviewRuntime{IEC104EnvelopeOpen: comp.IEC104EnvelopeOpen, GateAdmit: GateAdmitName(comp.GateAdmit)}
	switch {
	case !comp.SteersIEC104(&snap):
		runtime.Reason = "IEC 104 envelope not used by this candidate"
	case comp.IEC104EnvelopeOpen:
		runtime.Reason = "IEC 104 envelope open: candidate queue is owned by this engine"
	default:
		runtime.Reason = "IEC 104 envelope closed: candidate queue is not owned by this engine"
	}
	switch {
	case !comp.SteersGate():
		runtime.GateAdmitReason = "scanning gate not used by this candidate"
	case comp.GateAdmit == enforce.GateAdmitOpen:
		runtime.GateAdmitReason = "scanning gate open: new gated connections are delivered to the scanner"
	case comp.GateAdmit == enforce.GateAdmitPass:
		runtime.GateAdmitReason = "scanning gate passing: new gated connections pass unscanned while a listener or the gate routing is down (open fail policy)"
	default:
		runtime.GateAdmitReason = "scanning gate refusing: new gated connections are reset until the listeners and the gate routing are up; ICS endpoints pass ungated"
	}
	ruleset, err := comp.CompileFirewall(&snap)
	if err != nil {
		return RulesetPreview{}, err
	}
	return RulesetPreview{Snapshot: snap, Ruleset: ruleset, Runtime: runtime, Warnings: comp.RuleWarnings(&snap)}, nil
}
