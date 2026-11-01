// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/coverage"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

// Record failed replay as well as failed compensation. An engine ruleset can
// still be valid while services/dataplane replay failed before reaching it.
func recordRuntimeApplyResult(ctx context.Context, store config.Store, applyErr error) error {
	runtimeStore, ok := store.(config.RuntimeStore)
	if !ok {
		return applyErr
	}
	fault := ""
	if applyErr != nil {
		fault = applyErr.Error()
	}
	healthCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	return errors.Join(applyErr, runtimeStore.SetRuntimeApplyFault(healthCtx, fault))
}

// rulesetObservation is one read of the engine's ruleset status, shared by
// the health objects derived from it. err is set when the engine is absent
// or could not answer within the health budget.
type rulesetObservation struct {
	status dpengine.RulesetStatus
	err    error
}

func observeRuleset(ctx context.Context, engine EngineClient) rulesetObservation {
	if engine == nil {
		return rulesetObservation{err: errors.New("no engine")}
	}
	status, err := engine.RulesetStatus(ctx)
	if err == nil {
		err = ctx.Err()
	}
	return rulesetObservation{status: status, err: err}
}

// enforcementHealth reports general firewall state separately from IEC104.
// Snapshot faults take precedence over configured mode: failed compensation or
// replay makes the live state uncertain, including a failed disable request.
func enforcementHealth(snapshot config.HealthSnapshot, snapshotErr error, ruleset rulesetObservation, protection dpengine.ProtectionStatus) gin.H {
	health := gin.H{"state": "unknown", "reason": "configuration health unavailable"}
	if snapshotErr != nil {
		return health
	}
	if snapshot.ApplyFault != "" {
		// Health is unauthenticated; nft diagnostics can contain the full policy.
		health["state"] = "unavailable"
		health["reason"] = "configuration replay or recovery failed; runtime synchronization is uncertain"
		return health
	}
	if snapshot.Config == nil {
		return health
	}
	switch protection.State {
	case "protecting":
		health["state"], health["reason"] = "enforcing", ""
		if ruleset.err == nil && ruleset.status.SchedulePlanner != nil && ruleset.status.SchedulePlanner.State == dpengine.SchedulePlannerDegraded {
			health["state"], health["reason"] = "degraded", "schedule planner degraded"
			// Preserve the planner's public summaries, never its diagnostics.
			switch reason := ruleset.status.SchedulePlanner.Reason; reason {
			case "schedule refill failing", "schedule horizon exhausted", "schedule horizon ends within an hour":
				health["reason"] = reason
			}
		}
	case "degraded":
		health["state"], health["reason"] = "degraded", "rule-hit logging unavailable; nft policy enforcing"
	case "pending", "failed":
		health["state"], health["reason"] = "unavailable", "protection "+protection.State
	case "disabled":
		health["state"], health["reason"] = "disabled", ""
	default:
		health["reason"] = "engine protection status unavailable"
	}
	return health
}

// rulesetInstalled reports whether the engine has a ruleset in force. A
// failed apply leaves the installed one, so the status can carry both.
func rulesetInstalled(status dpengine.RulesetStatus) bool {
	return !status.AppliedAt.IsZero() && status.Ruleset != ""
}

// icsEnforcementHealth summarizes the applied ICS rule coverage as counts
// only: health is unauthenticated, so it names no rule or exclusion.
func icsEnforcementHealth(ruleset rulesetObservation) coverage.Summary {
	if ruleset.err != nil {
		return coverage.Summary{State: coverage.SummaryUnknown}
	}
	return coverage.Summarize(ruleset.status.ICSCoverage)
}
