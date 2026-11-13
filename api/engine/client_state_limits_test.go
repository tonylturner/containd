// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStateLimitsClient(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		fail       bool
	}{
		{"live", `{"tables":[{"table":"flows","entries":2}],"budget":{"limit":67108864,"byCategory":{"stream":12}}}`, 200, false},
		{"unavailable", `{"error":"offline"}`, 503, true},
		{"invalid", `broken`, 200, true},
		{"empty", `{}`, 200, true},
		{"null", `null`, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/internal/diagnostics/state-limits" {
					t.Errorf("request: %s %s", r.Method, r.URL.Path)
				}
				if tc.name == "invalid" {
					http.Error(w, tc.body, tc.status)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				if err := json.NewEncoder(w).Encode(json.RawMessage(tc.body)); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()
			c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
			got, err := c.StateLimits(context.Background())
			if (err != nil) != tc.fail {
				t.Fatalf("error=%v", err)
			}
			if !tc.fail && (len(got.Tables) != 1 || got.Tables[0].Entries != 2 || got.Budget.ByCategory["stream"] != 12) {
				t.Fatal(got)
			}
		})
	}
}
