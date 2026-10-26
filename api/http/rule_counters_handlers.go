// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

// RuleCountersClient reads the per-rule counters of the applied ruleset.
type RuleCountersClient interface {
	RuleCounters(ctx context.Context) (dpengine.RuleCounters, error)
}

// ruleCountersHandler serves the kernel per-rule packet and byte counters
// of the applied ruleset, which start at zero on each apply (since).
func ruleCountersHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		rc, ok := engine.(RuleCountersClient)
		if !ok || rc == nil {
			apiError(c, http.StatusServiceUnavailable, "engine unavailable: rule counters require a live engine")
			return
		}
		counters, err := rc.RuleCounters(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if counters.Rules == nil {
			counters.Rules = []enforce.RuleCount{}
		}
		c.JSON(http.StatusOK, counters)
	}
}
