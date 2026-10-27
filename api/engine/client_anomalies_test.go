// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListAnomaliesRequestAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       string
	}{
		{"unavailable", `{"error":"anomaly detector unavailable"}`, http.StatusServiceUnavailable, `engine anomalies status 503: {"error":"anomaly detector unavailable"}`},
		{"null list", "null", http.StatusOK, "invalid engine anomaly list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/internal/anomalies" || r.URL.Query().Get("limit") != "5" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			list, err := NewHTTPClient(srv.URL).ListAnomalies(context.Background(), 5)
			if err == nil || err.Error() != tc.want || list != nil {
				t.Fatalf("ListAnomalies = %#v, %v; want nil, %q", list, err, tc.want)
			}
		})
	}
}

func TestClearAnomaliesReportsEngineFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/internal/anomalies" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := NewHTTPClient(srv.URL).ClearAnomalies(context.Background()); err == nil || err.Error() != "engine anomalies clear status 500: boom" {
		t.Fatalf("ClearAnomalies error = %v", err)
	}
}
