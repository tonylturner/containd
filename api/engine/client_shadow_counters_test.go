// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestShadowCounters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/firewall/shadow-counters" {
			t.Errorf("request %s %s", r.Method, r.URL)
		}
		_, _ = w.Write([]byte(`{"available":true,"snapshotVersion":"s","since":"2026-10-30T12:00:00Z","unit":"messages","rules":[{"ruleId":"r","shadowMatches":1,"wouldAllow":0,"wouldDeny":1}]}`))
	}))
	defer srv.Close()
	got, err := NewHTTPClient(srv.URL).ShadowCounters(context.Background())
	if err != nil || !got.Available || got.SnapshotVersion != "s" || got.Since == nil || len(got.Rules) != 1 || got.Rules[0].WouldDeny != 1 {
		t.Fatal(got, err)
	}
}
