// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"encoding/json"
	"net/http"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/engine"
)

// previewRulesetHandler compiles a candidate without configuring or applying it.
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
		var cfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := config.ValidateManagementReservation(&cfg, dp.ManagementReservation()); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		snap, err := compile.CompileSnapshot(&cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !cfg.DataPlane.Enforcement {
			writeJSON(w, engine.RulesetPreview{
				Snapshot: snap,
				Runtime:  engine.RulesetPreviewRuntime{Reason: "Enforcement is disabled; nothing would be applied"},
			})
			return
		}
		preview, err := dp.PreviewRuleset(snap, compilerSettings(cfg.DataPlane))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, preview)
	}
}
