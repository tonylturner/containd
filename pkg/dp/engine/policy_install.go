// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ErrResolvedPolicyChanged requires a new admitted attempt, not an owner retry.
var ErrResolvedPolicyChanged = errors.New("changed resolved policy requires a new apply ID")

// ApplyRules installs and publishes one policy under the verdict publication
// fence. A failed install leaves the previous policy intact. A failed sweep
// leaves the new policy installed, unhealthy, and blocks parity/index reuse.
func (e *Engine) ApplyRules(ctx context.Context, snap rules.Snapshot) (applyErr error) {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	before := e.ruleSnap.Load()
	observe := true
	defer func() {
		if observe {
			e.protectionInstalled(applyErr, e.ruleSnap.Load() != before)
		}
	}()
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
	var discover func() ([]string, error)
	if e.compiler != nil {
		discover = mgmtpath.Devices
	}
	input, err := protectionPolicyInput(snap, signature, discover)
	if err != nil {
		return err
	}
	p := e.protection
	p.mu.Lock()
	// Only revision-bound protocol attempts enforce immutable resolved input.
	// Operational refills retain the installed association outside this path.
	bound := p.status.metadata().Valid()
	if bound && p.ruleInputApply == p.status.ApplyID && !bytes.Equal(p.ruleInput, input) {
		p.mu.Unlock()
		observe = false
		return ErrResolvedPolicyChanged
	}
	if bound {
		p.ruleInputApply, p.ruleInput = p.status.ApplyID, bytes.Clone(input)
	}
	adopt := bound && !p.applying && !p.installFailed && p.status.Installed != nil && bytes.Equal(p.installedInput, input)
	p.mu.Unlock()
	if adopt {
		return nil
	}
	e.BeginProtection(e.Protection().BootID, e.Protection().ApplyID)
	oldParity := e.admission.parity
	changed := e.admission.installed && signature != e.admission.signature
	snap.AdmissionParity = oldParity
	if changed {
		snap.AdmissionParity ^= markabi.ParityBit
	}
	if err := e.installAndPublishRules(ctx, &snap, signature); err != nil {
		e.recordApplyFailure(snap.Version, err)
		return err
	}
	if e.compiler != nil {
		// Stale parity already rematches the installed policy. Sweeping must
		// not stall packet verdicts; lifecycleMu still excludes the next
		// flip and any reuse of retired gate indices until it completes.
		if err := e.sweepAdmission(ctx, old, oldParity, changed); err != nil {
			e.recordApplyFailure(snap.Version, err)
			return err
		}
	}
	p.update(func() { p.installedInput = bytes.Clone(input) })
	return nil
}

// installAndPublishRules fences hook replacement through publication and cache
// invalidation, but not the subsequent conntrack sweeps. Caller owns lifecycleMu.
func (e *Engine) installAndPublishRules(ctx context.Context, snap *rules.Snapshot, signature [32]byte) error {
	e.policyMu.Lock()
	defer e.policyMu.Unlock()
	var compiled string
	var warnings []enforce.RuleWarning
	if e.compiler != nil {
		if err := e.recoverAdmission(ctx); err != nil {
			return err
		}
		start := time.Now()
		e.compiler.GateAdmit = e.gateAdmit
		var err error
		if compiled, err = e.gate.apply(ctx, e.compiler, e.applier, snap); err != nil {
			return err
		}
		metrics.NFTablesApplyDuration.Observe(time.Since(start).Seconds())
		warnings = e.compiler.RuleWarnings(snap)
		e.sessions.health.clear(faultAddresses)
	}
	appliedAt := time.Now().UTC()
	e.ruleSnap.Install(snap, appliedAt)
	if e.compiler != nil {
		acts := e.sessions.installPolicy(snap, true)
		// Hook replacement already dropped these skbs. Do not send a
		// deferred verdict or wait for read-lock-taking callbacks here.
		e.capture.RetireFlushed()
		acts.drops = nil
		e.sessions.finish(acts)
	} else {
		e.sessions.setPolicy(snap)
	}
	e.verdictCache.Flush()
	metrics.RulesCount.Set(float64(len(snap.Firewall)))
	e.rulesetStatus.Store(&RulesetStatus{Ruleset: compiled, SnapshotVersion: snap.Version, AppliedAt: appliedAt, Warnings: warnings})
	e.resetExclusionHits()
	if e.compiler != nil {
		e.admission.installed, e.admission.signature, e.admission.parity = true, signature, snap.AdmissionParity
	}
	return nil
}
