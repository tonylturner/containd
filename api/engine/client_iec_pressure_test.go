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

func TestIEC104DiagnosticsClient(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		fail       bool
	}{
		{"live", `{"heldPackets":3,"heldBytes":12,"limits":{"sessions":4096},"aborts":{"deny":2}}`, 200, false},
		{"unavailable", `{"error":"offline"}`, 503, true},
		{"invalid", `broken`, 200, true},
		{"empty", `{}`, 200, true},
		{"null", `null`, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/internal/diagnostics/iec104" {
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
			got, err := c.IEC104Diagnostics(context.Background())
			if (err != nil) != tc.fail {
				t.Fatalf("error=%v", err)
			}
			if !tc.fail && (got.HeldPackets != 3 || got.Limits.Sessions != 4096 || got.Aborts["deny"] != 2) {
				t.Fatal(got)
			}
		})
	}
}
