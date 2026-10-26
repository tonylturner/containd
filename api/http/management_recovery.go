// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// RecoverySnapshot deliberately contains no stored policy or service input.
// The compiler supplies established traffic, loopback and the env-backed
// reserved INPUT allow; every new forwarded connection is dropped.
func RecoverySnapshot() rules.Snapshot {
	return rules.Snapshot{Version: "management-recovery", Default: rules.ActionDeny}
}

// ApplyBootConfig shares the promotion/replay lock so a delayed recovery apply
// can never overwrite a newer safe commit, rollback or reset.
func ApplyBootConfig(ctx context.Context, store config.Store, engine EngineClient, services ServicesApplier) (warnings []string, applyErr error) {
	runningConfigApplyMu.Lock()
	defer runningConfigApplyMu.Unlock()
	err := config.CheckManagementBootFault(ctx, store)
	if err == nil {
		return applyRunningConfigLocked(ctx, store, engine, services, nil)
	}
	if !errors.Is(err, config.ErrManagementBootFault) {
		return nil, err
	}
	defer func() { applyErr = recordRuntimeApplyResult(ctx, store, applyErr) }()
	if engine == nil {
		return nil, errors.New("recovery engine unavailable")
	}
	dp := config.DataPlaneConfig{Enforcement: true}
	if err := config.ValidateManagementDataPlane(dp, config.ReservationForStore(store)); err != nil {
		return nil, err
	}
	if err := engine.Configure(ctx, dp); err != nil {
		return nil, fmt.Errorf("recovery dataplane: %w", err)
	}
	// Unlike normal best-effort infrastructure apply, a failure here must not
	// be downgraded to a warning or reported as successful recovery.
	if err := engine.ApplyRules(ctx, RecoverySnapshot()); err != nil {
		return nil, fmt.Errorf("recovery ruleset: %w", err)
	}
	return nil, nil
}

// Observe the engine, not a successful HTTP POST or the guard's health. A
// restarted/unreachable engine must never be advertised as fail-closed.
func managementRecoveryStatus(ctx context.Context, store config.Store, engine EngineClient) string {
	if engine == nil {
		return "recovery pending: engine unavailable"
	}
	status, err := engine.RulesetStatus(ctx)
	if err != nil {
		return "recovery pending: " + err.Error()
	}
	if status.Error != "" {
		return "recovery failed: " + status.Error
	}
	compiler := enforce.NewCompiler()
	compiler.ManagementReservation = config.ReservationForStore(store)
	snapshot := RecoverySnapshot()
	expected, err := compiler.CompileFirewall(&snapshot)
	if err != nil || status.AppliedAt.IsZero() || status.Ruleset != expected {
		return "recovery pending: ruleset not applied"
	}
	return "recovery: new transit dropped"
}
