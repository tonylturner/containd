// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

// installedRulesetStatus is the engine's status of the installed ruleset
// without its compiled text, which stays with the admin-only preview.
// Installed tells whether a ruleset is in force, which the text alone showed.
type installedRulesetStatus struct {
	dpengine.RulesetStatus
	// Ruleset shadows the embedded text in JSON; it is always empty, so
	// the field is omitted.
	Ruleset   string `json:"ruleset,omitempty"`
	Installed bool   `json:"installed"`
}

// getInstalledRulesetStatusHandler reports the installed ruleset's status
// to any authenticated user without compiling the candidate: the failed
// apply and the schedule planner state behind degraded enforcement health.
func getInstalledRulesetStatusHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusServiceUnavailable, "engine unavailable")
			return
		}
		status, err := engine.RulesetStatus(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, "engine ruleset status unavailable: "+err.Error())
			return
		}
		c.JSON(http.StatusOK, installedRulesetStatus{RulesetStatus: status, Installed: rulesetInstalled(status)})
	}
}
