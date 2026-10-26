// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/services"
)

// avOperator is the engine AV manager's operational surface.
type avOperator interface {
	Status(ctx context.Context) map[string]any
	RunFreshclamNow() error
	ListDefinitions() (services.AVDefinitionList, error)
	UploadDefinition(ctx context.Context, name string, r io.Reader) (services.AVDefinition, error)
	DeleteDefinition(ctx context.Context, name string) error
}

func registerAVHandlers(mux *http.ServeMux, av avOperator) {
	mux.HandleFunc("/internal/av/status", avStatusHandler(av))
	mux.HandleFunc("/internal/av/update", avUpdateHandler(av))
	mux.HandleFunc("/internal/av/defs", avDefsHandler(av))
}

func avError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, services.ErrAVInvalid):
		code = http.StatusBadRequest
	case errors.Is(err, services.ErrAVConflict):
		code = http.StatusConflict
	case errors.Is(err, services.ErrAVStopped):
		code = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), code)
}

func avStatusHandler(av avOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, av.Status(r.Context()))
	}
}

func avUpdateHandler(av avOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := av.RunFreshclamNow(); err != nil {
			avError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"status":"freshclam started"}`+"\n")
	}
}

// avDefsHandler lists (GET), uploads a raw body named by ?name= (POST) and
// deletes (DELETE ?name=) custom definitions.
func avDefsHandler(av avOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		switch r.Method {
		case http.MethodGet:
			list, err := av.ListDefinitions()
			if err != nil {
				avError(w, err)
				return
			}
			writeJSON(w, list)
		case http.MethodPost:
			// UploadDefinition reads at most MaxAVDefinitionBytes+1 bytes.
			def, err := av.UploadDefinition(r.Context(), name, r.Body)
			if err != nil {
				avError(w, err)
				return
			}
			writeJSON(w, def)
		case http.MethodDelete:
			if err := av.DeleteDefinition(r.Context(), name); err != nil {
				avError(w, err)
				return
			}
			writeJSON(w, map[string]string{"status": "deleted", "file": name})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
