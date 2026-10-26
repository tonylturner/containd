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
func enforcementHealth(snapshot config.HealthSnapshot, snapshotErr error, ruleset rulesetObservation) gin.H {
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
	if !snapshot.Config.DataPlane.Enforcement {
		health["state"] = "disabled"
		health["reason"] = ""
		return health
	}
	status := ruleset.status
	switch {
	case ruleset.err != nil:
		health["reason"] = "engine ruleset status unavailable"
	case status.Error != "":
		health["state"] = "unavailable"
		health["reason"] = "ruleset apply failed"
	case status.AppliedAt.IsZero() || status.Ruleset == "":
		health["state"] = "unavailable"
		health["reason"] = "no enforced ruleset applied"
	default:
		health["state"] = "enforcing"
		health["reason"] = ""
	}
	return health
}

// icsEnforcementHealth summarizes the applied ICS rule coverage as counts
// only: health is unauthenticated, so it names no rule or exclusion.
func icsEnforcementHealth(ruleset rulesetObservation) coverage.Summary {
	if ruleset.err != nil {
		return coverage.Summary{State: coverage.SummaryUnknown}
	}
	return coverage.Summarize(ruleset.status.ICSCoverage)
}
