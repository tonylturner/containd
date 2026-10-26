// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"encoding/json"
	"net/http"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// rulesetPreviewRequest carries a candidate and the snapshot management
// compiled from it. Management compiles, as for an apply, so the snapshot's
// management INPUT admits the listeners management resolves and has bound,
// which a separate engine process cannot see.
type rulesetPreviewRequest struct {
	Config   *config.Config `json:"config"`
	Snapshot rules.Snapshot `json:"snapshot"`
}

// previewRulesetHandler compiles a candidate's ruleset without configuring
// or applying it.
func previewRulesetHandler(dp *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if dp == nil {
			http.Error(w, "engine unavailable", http.StatusServiceUnavailable)
			return
		}
		var req rulesetPreviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Config == nil {
			http.Error(w, "config is required", http.StatusBadRequest)
			return
		}
		if err := config.ValidateManagementReservation(req.Config, dp.ManagementReservation()); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !req.Config.DataPlane.Enforcement {
			writeJSON(w, engine.RulesetPreview{
				Snapshot: req.Snapshot,
				Runtime:  engine.RulesetPreviewRuntime{Reason: "Enforcement is disabled; nothing would be applied"},
			})
			return
		}
		preview, err := dp.PreviewRuleset(req.Snapshot, compilerSettings(req.Config.DataPlane))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, preview)
	}
}
