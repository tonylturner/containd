// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tonylturner/containd/pkg/dp/engine"
)

// ruleCountersHandler serves the per-rule counters of the applied ruleset.
func ruleCountersHandler(dp *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		counters, err := dp.RuleCounters(ctx)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, engine.ErrRuleCountersUnavailable) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, err.Error(), status)
			return
		}
		writeJSON(w, counters)
	}
}
