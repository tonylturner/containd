// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"net/http"

	"github.com/tonylturner/containd/pkg/dp/engine"
)

func shadowCountersHandler(dp *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, dp.ShadowCounters())
	}
}
