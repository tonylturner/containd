// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"

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
