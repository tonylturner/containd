// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListConntrackBackendErrorDetail(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"permission", "ctnetlink: operation not permitted\n", "engine conntrack status 503: ctnetlink: operation not permitted"},
		{"interrupted", "conntrack dump interrupted", "engine conntrack status 503: conntrack dump interrupted"},
		{"empty", "", "engine conntrack status 503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/conntrack" || r.URL.Query().Get("limit") != "5" {
					t.Errorf("unexpected request %s", r.URL)
				}
				http.Error(w, tc.body, http.StatusServiceUnavailable)
			}))
			defer srv.Close()
			entries, err := NewHTTPClient(srv.URL).ListConntrack(context.Background(), 5)
			if err == nil || strings.TrimSpace(err.Error()) != tc.want || entries != nil {
				t.Fatalf("ListConntrack = %+v, %v; want nil, %q", entries, err, tc.want)
			}
		})
	}
}
