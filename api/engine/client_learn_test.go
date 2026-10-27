// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLearnClientReportsEngineFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /internal/learn/profiles", "GET /internal/learn/rules":
			_, _ = w.Write([]byte("null"))
		case "DELETE /internal/learn":
			http.Error(w, `{"error":"learner unavailable"}`, http.StatusServiceUnavailable)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
	}))
	defer srv.Close()
	client := NewHTTPClient(srv.URL)
	ctx := context.Background()
	if profiles, err := client.ListLearnProfiles(ctx); err == nil || err.Error() != "invalid engine learn profile list" || profiles != nil {
		t.Fatalf("ListLearnProfiles = %#v, %v", profiles, err)
	}
	if generated, err := client.GenerateLearnRules(ctx); err == nil || err.Error() != "invalid engine learn rule list" || generated != nil {
		t.Fatalf("GenerateLearnRules = %#v, %v", generated, err)
	}
	if err := client.ClearLearnData(ctx); err == nil || err.Error() != `engine learn clear status 503: {"error":"learner unavailable"}` {
		t.Fatalf("ClearLearnData error = %v", err)
	}
}

func TestLearnListStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := NewHTTPClient(srv.URL).ListLearnProfiles(context.Background()); err == nil || err.Error() != "engine learn profiles status 503: down" {
		t.Fatalf("ListLearnProfiles error = %v", err)
	}
	if _, err := NewHTTPClient(srv.URL).GenerateLearnRules(context.Background()); err == nil || err.Error() != "engine learn rules status 503: down" {
		t.Fatalf("GenerateLearnRules error = %v", err)
	}
}
