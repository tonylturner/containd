// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/tonylturner/containd/pkg/common/trust"
)

// maxTrustBody bounds a distributed CA bundle request.
const maxTrustBody = 1 << 20

// trustApplier receives management's additional CA bundle. The engine's
// outbound TLS clients (ICAP and FreshClam) verify servers with it.
type trustApplier interface {
	SetTrust(ctx context.Context, b trust.Bundle) error
	TrustRevision() string
}

func trustHandler(t trustApplier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]string{"revision": t.TrustRevision()})
		case http.MethodPost:
			var b trust.Bundle
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTrustBody)).Decode(&b); err != nil {
				http.Error(w, "invalid trusted CA request: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := t.SetTrust(r.Context(), b); err != nil {
				avError(w, err)
				return
			}
			writeJSON(w, map[string]string{"revision": b.Revision})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
