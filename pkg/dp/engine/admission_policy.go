// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type admissionPolicy struct {
	initialized bool
	installed   bool
	parity      uint32
	signature   [32]byte
	dirty       bool
	gateDirty   bool
}

// policySignature excludes install metadata and parity, but includes everything
// used by permission, scope, parsing and translation. JSON canonicalizes maps.
func (e *Engine) policySignature(snap rules.Snapshot) ([32]byte, error) {
	return e.policySignatureForQueue(snap, e.nfqueueGroup)
}

func (e *Engine) policySignatureForQueue(snap rules.Snapshot, queue uint16) ([32]byte, error) {
	snap.Version, snap.AdmissionParity = "", 0
	if snap.Default != rules.ActionAllow {
		snap.Default = rules.ActionDeny
	}
	snap.DPIMode = rules.EffectiveMode("", snap.DPIMode)
	snap.Firewall = slices.Clone(snap.Firewall)
	for i := range snap.Firewall {
		codes := slices.Clone(snap.Firewall[i].ICS.FunctionCode)
		slices.Sort(codes)
		snap.Firewall[i].ICS.FunctionCode = slices.Compact(codes)
		if snap.Firewall[i].ICS.Protocol != "" {
			snap.Firewall[i].ICS.Mode = rules.EffectiveMode(snap.Firewall[i].ICS.Mode, snap.DPIMode)
		}
	}
	// Management listeners and descriptive NAT metadata do not change S2/S4.
	snap.LocalInput = nil
	// IDS event selectors produce alerts, not packet permission.
	snap.IDS = rules.IDSConfig{Enabled: snap.IDS.Enabled}
	snap.NAT.PortForwards = slices.Clone(snap.NAT.PortForwards)
	for i := range snap.NAT.PortForwards {
		snap.NAT.PortForwards[i].Description = ""
	}
	parsing := map[string]string{}
	for _, port := range ics.DecoderPorts() {
		parsing[port.Protocol] = string(e.ICSParsing(port.Protocol))
	}
	var decoders []string
	for _, decoder := range e.dpiMgr.Decoders() {
		decoders = append(decoders, fmt.Sprintf("%T", decoder))
	}
	slices.Sort(decoders)
	input := struct {
		Snapshot               rules.Snapshot
		Parsing                map[string]string
		Decoders               []string
		Exclusions             []DPIExclusion
		DPIEnabled, InspectAll bool
		Queue                  uint16
	}{snap, parsing, decoders, e.dpiExclusions, e.dpiEnabled, e.inspectAll, queue}
	b, err := canonicalPolicyJSON(input)
	return sha256.Sum256(b), err
}

// recoverAdmission runs before installation/activation and before another flip.
// A failed masked sweep must never allow parity or a retired gate index to cycle.
// Caller holds lifecycleMu then policyMu exclusively.
func (e *Engine) recoverAdmission(ctx context.Context) error {
	a := &e.admission
	if !a.initialized || a.dirty {
		if _, err := e.clearMarks(ctx, markabi.AdmittedBit, markabi.AdmittedBit, markabi.AdmittedBit); err != nil {
			a.dirty = true
			return e.policyFault(faultAdmission, err)
		}
		a.dirty = false
		e.iec.health.clear(faultAdmission)
	}
	if !a.initialized {
		// No allocation from a prior process is trustworthy. Clear only the
		// zone field, retaining ownership, selection and all unrelated bits.
		if _, err := e.clearMarks(ctx, enforce.GateCtMark, enforce.GateCtMark, enforce.GateZoneCtMask); err != nil {
			a.gateDirty = true
			return e.policyFault(faultGateZones, err)
		}
	} else if a.gateDirty {
		live := map[uint8]bool{}
		if snap := e.ruleSnap.Load(); snap != nil {
			for _, z := range snap.Gate.Zones {
				live[z.Index] = true
			}
		}
		for index := 1; index <= 255; index++ {
			if live[uint8(index)] {
				continue
			}
			if err := e.clearGateIndex(ctx, uint8(index)); err != nil {
				return err
			}
		}
	}
	a.initialized, a.gateDirty = true, false
	e.iec.health.clear(faultGateZones)
	return nil
}

func (e *Engine) clearGateIndex(ctx context.Context, index uint8) error {
	match := enforce.GateCtMark | uint32(index)<<enforce.GateZoneCtShift
	if _, err := e.clearMarks(ctx, enforce.GateCtMark|enforce.GateZoneCtMask, match, enforce.GateZoneCtMask); err != nil {
		e.admission.gateDirty = true
		return e.policyFault(faultGateZones, err)
	}
	return nil
}

// sweepAdmission runs after publication with lifecycleMu held, not policyMu:
// stale admissions already rematch, while the next flip/index reuse must wait.
func (e *Engine) sweepAdmission(ctx context.Context, old *rules.Snapshot, oldParity uint32, changed bool) error {
	// Complete both classes even if the first sweep fails. Their dirty state
	// is independent, and neither can be reused until recovery succeeds.
	var failure error
	if changed {
		if _, err := e.clearMarks(ctx, markabi.AdmissionCtMask, markabi.AdmittedBit|oldParity, markabi.AdmittedBit); err != nil {
			e.admission.dirty = true
			failure = e.policyFault(faultAdmission, err)
		}
	}
	if old != nil {
		current := e.ruleSnap.Load()
		live := map[string]bool{}
		for _, z := range current.Gate.Zones {
			live[z.Name] = true
		}
		for _, z := range old.Gate.Zones {
			if !live[z.Name] {
				if err := e.clearGateIndex(ctx, z.Index); err != nil {
					failure = err
				}
			}
		}
	}
	return failure
}

func (e *Engine) policyFault(cause string, err error) error {
	err = fmt.Errorf("%s: %w", cause, err)
	e.iec.health.fault(cause, err.Error())
	return err
}
