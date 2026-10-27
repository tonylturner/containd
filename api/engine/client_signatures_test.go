// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/signatures"
)

func TestSignatureClientReportsEngineFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.RequestURI() {
		case "GET /internal/signatures", "GET /internal/signatures/matches?limit=3":
			_, _ = w.Write([]byte("null"))
		case "POST /internal/signatures", "DELETE /internal/signatures?id=a+b%2Fc":
			http.Error(w, "down", http.StatusServiceUnavailable)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer srv.Close()
	client := NewHTTPClient(srv.URL)
	ctx := context.Background()
	if sigs, err := client.ListSignatures(ctx); err == nil || err.Error() != "invalid engine signature list" || sigs != nil {
		t.Fatalf("ListSignatures = %#v, %v", sigs, err)
	}
	if matches, err := client.ListSignatureMatches(ctx, 3); err == nil || err.Error() != "invalid engine signature match list" || matches != nil {
		t.Fatalf("ListSignatureMatches = %#v, %v", matches, err)
	}
	if err := client.AddSignature(ctx, signatures.Signature{ID: "x"}); err == nil || err.Error() != "engine signature add status 503: down" {
		t.Fatalf("AddSignature error = %v", err)
	}
	if removed, err := client.RemoveSignature(ctx, "a b/c"); err == nil || err.Error() != "engine signature remove status 503: down" || removed {
		t.Fatalf("RemoveSignature = %v, %v", removed, err)
	}
}
