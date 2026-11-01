// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/coverage"
)

// getICSCoverageHandler reports the coverage of the candidate's and the
// applied ICS rules to any authenticated user, without the ruleset. Each
// side is reported independently: an unreadable or invalid candidate sets
// candidateError and omits candidate, an unreadable engine sets engineStatusError and
// omits applied, and neither hides the other.
func getICSCoverageHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		resp := gin.H{}
		if cfg, err := readCandidate(c, store); err != nil {
			resp["candidateError"] = "candidate config unavailable"
		} else if candidate, err := candidateCoverage(store, cfg); err != nil {
			resp["candidateError"] = err.Error()
		} else {
			resp["candidate"] = candidate
		}
		ruleset := observeRuleset(ctx, engine)
		if ruleset.err != nil {
			resp["engineStatusError"] = "engine ruleset status unavailable: " + ruleset.err.Error()
		} else {
			status := ruleset.status
			resp["applied"] = nonNilCoverage(status.ICSCoverage)
			if !status.AppliedAt.IsZero() {
				resp["appliedAt"] = status.AppliedAt
			}
			if status.Error != "" {
				resp["applyError"] = status.Error
			}
		}
		c.JSON(http.StatusOK, resp)
	}
}

// candidateCoverage is the static coverage of a candidate that passes the
// store's validation, as the ruleset preview and commit would compile it.
func candidateCoverage(store config.Store, cfg *config.Config) ([]coverage.Rule, error) {
	if err := config.ValidateForStore(store, cfg); err != nil {
		return nil, err
	}
	snap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		return nil, err
	}
	return nonNilCoverage(coverage.Evaluate(&snap, cfg.DataPlane.CoverageSettings())), nil
}

// nonNilCoverage keeps an empty list an empty JSON array, not null.
func nonNilCoverage(rs []coverage.Rule) []coverage.Rule {
	if rs == nil {
		return []coverage.Rule{}
	}
	return rs
}
