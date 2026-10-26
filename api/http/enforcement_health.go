// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
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

// Extend the existing enforcement object, keeping IEC104 queue/reset health
// independent of general ruleset availability. Never infer availability merely
// from a successful HTTP response or an inactive IEC104 policy.
func rulesetHealth(ctx context.Context, store config.Store, engine EngineClient) gin.H {
	health := gin.H{"rulesetAvailable": false, "rulesetReason": "engine unavailable", "configApplyError": ""}
	if engine != nil {
		status, err := engine.RulesetStatus(ctx)
		switch {
		case err != nil:
			health["rulesetReason"] = "engine ruleset status unavailable"
		case status.Error != "":
			health["rulesetReason"] = "ruleset apply failed"
		case status.AppliedAt.IsZero() || status.Ruleset == "":
			health["rulesetReason"] = "no enforced ruleset applied"
		default:
			health["rulesetAvailable"] = true
			health["rulesetReason"] = ""
		}
	}
	if runtimeStore, ok := store.(config.RuntimeStore); ok {
		fault, err := runtimeStore.RuntimeApplyFault(ctx)
		if err != nil {
			fault = "configuration apply health unavailable"
		}
		// Health is unauthenticated. Nft diagnostics can contain the complete
		// policy, so only authenticated commit responses expose their detail.
		if err == nil && fault != "" {
			fault = "configuration replay or recovery failed; runtime synchronization is uncertain"
		}
		health["configApplyError"] = fault
		if fault != "" {
			health["rulesetAvailable"] = false
			health["rulesetReason"] = fault
		}
	}
	return health
}
