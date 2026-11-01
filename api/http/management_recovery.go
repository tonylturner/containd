// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// RecoverySnapshot deliberately contains no stored policy, NAT or service
// input. The compiler supplies established traffic, loopback and the env-backed
// reserved INPUT allow; every new forwarded connection is dropped. Without a
// reservation the stored management listener access is the only management
// path, so recovery keeps exactly that access and nothing else from stored:
// the listeners management has bound, which are the appliance defaults when
// the stored ones could not be bound, and the stored listeners, on the
// interfaces that stored access grants management.
func RecoverySnapshot(stored *config.Config, r *mgmtpath.Reservation) rules.Snapshot {
	snap := rules.Snapshot{Version: config.ManagementRecoveryVersion, Default: rules.ActionDeny}
	if r == nil && stored != nil {
		snap.LocalInput = compile.ManagementLocalInput(stored)
	}
	return snap
}

// ApplyBootConfig shares the promotion/replay lock so a delayed recovery apply
// can never overwrite a newer safe commit, rollback or reset.
func ApplyBootConfig(ctx context.Context, store config.Store, engine EngineClient, services ServicesApplier) ([]string, error) {
	runningConfigApplyMu.Lock()
	defer runningConfigApplyMu.Unlock()
	err := config.CheckManagementBootFault(ctx, store)
	if err == nil {
		return applyRunningConfigLocked(ctx, store, engine, services, nil)
	}
	if !errors.Is(err, config.ErrManagementBootFault) {
		return nil, err
	}
	return applyRecoveryLocked(ctx, store, engine)
}

// reenterRecoveryLocked completes a running-state transition that failed
// at runtime from management recovery. The store restored the refused
// configuration without reapplying it (config.ApplyError.Recovery); the
// engine gets the recovery ruleset again, and its outcome is the
// transition's reapply result; its warnings are returned. Callers hold
// runningConfigApplyMu.
func reenterRecoveryLocked(ctx context.Context, store config.Store, engine EngineClient, transitionErr error) []string {
	var failure *config.ApplyError
	if !errors.As(transitionErr, &failure) || !failure.Recovery {
		return nil
	}
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	warnings, err := applyRecoveryLocked(recoveryCtx, store, engine)
	failure.ReapplyError = err
	return warnings
}

// applyRecoveryLocked applies management recovery to the engine: the
// fail-closed dataplane and RecoverySnapshot, then, without a reservation,
// the stored addresses of the interfaces it admits management on
// (recoveryAddresses). A failure to address them is a warning: the
// recovery ruleset is in force. Callers hold runningConfigApplyMu.
func applyRecoveryLocked(ctx context.Context, store config.Store, engine EngineClient) (warnings []string, applyErr error) {
	defer func() { applyErr = recordRuntimeApplyResult(ctx, store, applyErr) }()
	ctx = engineclient.NewApplyContext(ctx)
	if engine == nil {
		return nil, errors.New("recovery engine unavailable")
	}
	r := config.ReservationForStore(store)
	var stored *config.Config
	if r == nil {
		// Never drop transit with an INPUT chain that also drops management.
		var err error
		if stored, err = store.Load(ctx); err != nil {
			return nil, fmt.Errorf("recovery management access: %w", err)
		}
	}
	dp := config.DataPlaneConfig{Enforcement: true}
	if err := config.ValidateManagementDataPlane(dp, r); err != nil {
		return nil, err
	}
	if err := engine.Configure(ctx, dp); err != nil {
		return nil, fmt.Errorf("recovery dataplane: %w", err)
	}
	// Unlike normal best-effort infrastructure apply, a failure here must not
	// be downgraded to a warning or reported as successful recovery.
	snap := RecoverySnapshot(stored, r)
	if _, err := engine.ApplyRules(ctx, snap); err != nil {
		return nil, fmt.Errorf("recovery ruleset: %w", err)
	}
	if addressed := recoveryAddresses(stored, snap.LocalInput); len(addressed) > 0 {
		if err := engine.ConfigureInterfaces(ctx, addressed); err != nil {
			warnings = append(warnings, fmt.Sprintf("recovery interface addresses: %v", err))
		}
	}
	return warnings, nil
}

// Recovery states. Applied, pending and failed derive from what the engine
// reports it applied; inactive means no boot fault, and unknown that the
// fault could not be read.
const (
	recoveryInactive = "inactive"
	recoveryApplied  = "active"
	recoveryPending  = "pending"
	recoveryFailed   = "failed"
	recoveryUnknown  = "unknown"
)

// observeManagementRecovery reads the engine, not a successful HTTP POST or
// the guard's health. A restarted/unreachable engine must never be advertised
// as fail-closed. The engine compiles with authority management cannot see
// (its engine API path, its reservation), so recovery is recognized by the
// snapshot version of the ruleset the engine has installed, not by
// recompiling the ruleset here. A failed apply leaves the installed ruleset
// in force, so installed recovery stays applied whatever failed after it.
// detail may carry engine diagnostics and is for authenticated views only.
func observeManagementRecovery(ruleset rulesetObservation) (state, detail string) {
	status := ruleset.status
	switch {
	case ruleset.err != nil:
		return recoveryPending, ruleset.err.Error()
	case rulesetInstalled(status) && status.SnapshotVersion == config.ManagementRecoveryVersion:
		return recoveryApplied, "new transit dropped"
	case status.Error != "":
		return recoveryFailed, status.Error
	default:
		return recoveryPending, "ruleset not applied"
	}
}

func managementRecoveryStatus(ctx context.Context, engine EngineClient) string {
	if engine == nil {
		return "recovery pending: engine unavailable"
	}
	state, detail := observeManagementRecovery(observeRuleset(ctx, engine))
	switch state {
	case recoveryApplied:
		return "recovery: " + detail
	case recoveryFailed:
		return "recovery failed: " + detail
	default:
		return "recovery pending: " + detail
	}
}
