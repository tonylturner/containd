// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ApplyRules installs and publishes one policy under the verdict publication
// fence. A failed install leaves the previous policy intact. A failed sweep
// leaves the new policy installed, unhealthy, and blocks parity/index reuse.
func (e *Engine) ApplyRules(ctx context.Context, snap rules.Snapshot) error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if snap.DPIMode == "" {
		snap.DPIMode = e.dpiMode
	}
	if err := snap.ValidateIndustrialProtocols(); err != nil {
		return err
	}
	if err := enforce.ValidateManagementSnapshot(&snap, e.managementReservation); err != nil {
		return err
	}
	old := e.ruleSnap.Load()
	var previous []rules.GateZone
	if e.admission.installed && old != nil {
		previous = old.Gate.Zones
	}
	var err error
	if snap.Gate, err = snap.Gate.WithStableZoneIndices(previous); err != nil {
		return err
	}
	if err := snap.Gate.Validate(); err != nil {
		return err
	}
	if e.compiler != nil {
		snap.LocalIPv4ByDevice, err = e.localIPv4(&snap)
		if err != nil {
			return e.policyFault(faultAddresses, err)
		}
	}
	signature, err := e.policySignature(snap)
	if err != nil {
		return err
	}
	e.policyMu.Lock()
	defer e.policyMu.Unlock()
	var compiled string
	var warnings []enforce.RuleWarning
	oldParity := e.admission.parity
	changed := e.admission.installed && signature != e.admission.signature
	snap.AdmissionParity = oldParity
	if changed {
		snap.AdmissionParity ^= markabi.ParityBit
	}
	if e.compiler != nil {
		if err := e.recoverAdmission(ctx); err != nil {
			e.recordApplyFailure(snap.Version, err)
			return err
		}
		start := time.Now()
		e.compiler.GateAdmit = e.gateAdmit
		if compiled, err = e.gate.apply(ctx, e.compiler, e.applier, &snap); err != nil {
			e.recordApplyFailure(snap.Version, err)
			return err
		}
		metrics.NFTablesApplyDuration.Observe(time.Since(start).Seconds())
		warnings = e.compiler.RuleWarnings(&snap)
		e.iec.health.clear(faultAddresses)
	}
	appliedAt := time.Now().UTC()
	e.ruleSnap.Install(&snap, appliedAt)
	if e.compiler != nil {
		acts := e.iec.installPolicy(&snap, true)
		// Hook replacement already dropped these skbs. Do not send a
		// deferred verdict or wait for read-lock-taking callbacks here.
		e.capture.RetireFlushed()
		acts.drops = nil
		e.iec.finish(acts)
	} else {
		e.iec.setPolicy(&snap)
	}
	e.verdictCache.Flush()
	metrics.RulesCount.Set(float64(len(snap.Firewall)))
	e.rulesetStatus.Store(&RulesetStatus{Ruleset: compiled, SnapshotVersion: snap.Version, AppliedAt: appliedAt, Warnings: warnings})
	e.resetExclusionHits()
	if e.compiler != nil {
		e.admission.installed, e.admission.signature, e.admission.parity = true, signature, snap.AdmissionParity
		if err := e.sweepAdmission(ctx, old, oldParity, changed); err != nil {
			e.recordApplyFailure(snap.Version, err)
			return err
		}
	}
	return nil
}
