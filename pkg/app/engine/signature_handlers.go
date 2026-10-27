// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/signatures"
)

const (
	maxSignatureBody          = 1 << 20
	defaultSignatureMatchList = 100
)

// signaturesHandler lists loaded signatures on GET, adds a live signature on
// POST and removes the signature named by the id query parameter on DELETE.
// Live changes last until the engine restarts. A signature ID is unique: POST
// with an ID already loaded answers 409.
func signaturesHandler(dpEngine *engine.Engine) http.HandlerFunc {
	// writes serializes the ID check with the add so concurrent POSTs cannot
	// load two signatures with one ID.
	var writes sync.Mutex
	return func(w http.ResponseWriter, r *http.Request) {
		sigs := dpEngine.SignatureEngine()
		if sigs == nil {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "signature engine unavailable"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, sigs.List())
		case http.MethodPost:
			var sig signatures.Signature
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSignatureBody)).Decode(&sig); err != nil {
				http.Error(w, "invalid signature JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := sig.Validate(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writes.Lock()
			defer writes.Unlock()
			if signatureLoaded(sigs, sig.ID) {
				http.Error(w, "signature already exists", http.StatusConflict)
				return
			}
			sigs.Add(sig)
			writeJSON(w, sig)
		case http.MethodDelete:
			id := strings.TrimSpace(r.URL.Query().Get("id"))
			if id == "" {
				http.Error(w, "missing signature id", http.StatusBadRequest)
				return
			}
			writes.Lock()
			defer writes.Unlock()
			if !sigs.Remove(id) {
				http.Error(w, "signature not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// signatureMatchesHandler lists recent signature matches, newest first.
func signatureMatchesHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sigs := dpEngine.SignatureEngine()
		if sigs == nil {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "signature engine unavailable"})
			return
		}
		writeJSON(w, sigs.Matches(parseLimit(r, defaultSignatureMatchList)))
	}
}

func signatureLoaded(sigs *signatures.Engine, id string) bool {
	for _, s := range sigs.List() {
		if s.ID == id {
			return true
		}
	}
	return false
}
