// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"encoding/json"
	"net/http"

	"github.com/tonylturner/containd/pkg/dp/engine"
)

// POST /internal/rules/preview accepts an entry and candidate forward matches and returns the public
// rule-impact response without mutating the live snapshot or enforcement state.
func previewRuleHandler(dp *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if dp == nil {
			http.Error(w, "engine unavailable", http.StatusServiceUnavailable)
			return
		}
		var request engine.PreviewRuleRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, dp.PreviewCandidateRule(request))
	}
}
