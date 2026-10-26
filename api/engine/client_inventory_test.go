// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/inventory"
)

func TestIEC104InventoryClient(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		fail       bool
	}{
		{"live", "", 200, false}, {"offline", `{"error":"unavailable"}`, 503, true},
		{"null", "null", 200, true}, {"empty", "{}", 200, true}, {"invalid", "!", 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/inventory" || r.URL.Query().Get("section") != "iec104" {
					t.Error(r.URL)
				}
				if tc.name == "invalid" {
					http.Error(w, "not JSON", http.StatusOK)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				if tc.body != "" {
					_ = json.NewEncoder(w).Encode(json.RawMessage(tc.body))
					return
				}
				_ = json.NewEncoder(w).Encode(inventory.New().SnapshotIEC104())
			}))
			defer srv.Close()
			c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
			s, err := c.IEC104Inventory(context.Background())
			if (err != nil) != tc.fail {
				t.Fatal(s, err)
			}
			if !tc.fail && (s.Pairs == nil || s.Limits.Pairs != inventory.MaxIEC104Pairs) {
				t.Fatal(s)
			}
		})
	}
}
