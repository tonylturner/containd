// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"net/http"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/engine"
)

// Anomaly list bounds match the management API: limit defaults to 200 and
// values outside 1..5000 fall back to the default.
const (
	defaultAnomalyLimit = 200
	maxAnomalyLimit     = 5000
)

// anomaliesHandler lists recent protocol anomalies, newest first, on GET and
// clears the detector on DELETE.
func anomaliesHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		detector := dpEngine.AnomalyDetector()
		if detector == nil {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "anomaly detector unavailable"})
			return
		}
		if r.Method == http.MethodDelete {
			detector.Clear()
			writeJSON(w, map[string]string{"status": "cleared"})
			return
		}
		list := detector.Anomalies(anomalyLimit(r))
		if list == nil {
			list = []anomaly.Anomaly{}
		}
		writeJSON(w, list)
	}
}

func anomalyLimit(r *http.Request) int {
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= maxAnomalyLimit {
		return v
	}
	return defaultAnomalyLimit
}

// writeJSONStatus writes v as JSON with an explicit status code.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, v)
}
