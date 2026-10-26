// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"net/http"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/learn"
)

// learnHandler clears the ICS traffic learner on DELETE.
func learnHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return withLearner(dpEngine, http.MethodDelete, func(w http.ResponseWriter, l *learn.Learner) {
		l.Clear()
		writeJSON(w, map[string]string{"status": "cleared"})
	})
}

// learnProfilesHandler lists the learned ICS traffic profiles on GET.
func learnProfilesHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return withLearner(dpEngine, http.MethodGet, func(w http.ResponseWriter, l *learn.Learner) {
		writeJSON(w, l.Profiles())
	})
}

// learnRulesHandler returns the allowlist rules generated from the learned
// profiles on GET. Generating rules does not change learner state.
func learnRulesHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return withLearner(dpEngine, http.MethodGet, func(w http.ResponseWriter, l *learn.Learner) {
		writeJSON(w, l.GenerateRules())
	})
}

func withLearner(dpEngine *engine.Engine, method string, serve func(http.ResponseWriter, *learn.Learner)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		l := dpEngine.Learner()
		if l == nil {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "learner unavailable"})
			return
		}
		serve(w, l)
	}
}
