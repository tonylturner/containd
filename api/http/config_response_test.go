// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func assertConfigResponseHeader(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	// Inspect the headers actually sent, not the mutable writer's late headers.
	got := rec.Result().Header.Values("X-Containd-Config")
	if want == "" {
		if len(got) != 0 {
			t.Fatalf("unexpected config header %v (status=%d)", got, rec.Code)
		}
	} else if len(got) != 1 || got[0] != want {
		t.Fatalf("config header=%v want=%q (status=%d)", got, want, rec.Code)
	}
}

func configResponseStageCases() []candidateEndpointCase {
	cases := candidateEndpointCases()
	for _, path := range []string{"/config", "/config/import", "/config/candidate"} {
		cases = append(cases, candidateEndpointCase{method: "POST", path: path, body: config.DefaultConfig()})
	}
	// Multipart data is supplied by idsApplyRequest rather than the JSON helper.
	return append(cases, candidateEndpointCase{method: "POST", path: "/ids/import"})
}

// Used only by tests to check the complete registered route inventory. The
// production classifier is the persistence boundary, never a URL inventory.
func configResponseRouteState(method, route string) string {
	path := strings.TrimPrefix(route, "/api/v1")
	path = strings.NewReplacer(":id", "old", ":name", "spare").Replace(path)
	if path == "/firewall/ics-rules/old" {
		path = "/firewall/ics-rules/ics"
	}
	if method == http.MethodPost {
		switch path {
		case "/config/commit", "/config/commit_confirmed", "/config/confirm", "/config/rollback":
			return "committed"
		}
	}
	for _, test := range configResponseStageCases() {
		if method == test.method && path == test.path {
			return "staged"
		}
	}
	return ""
}

func TestConfigResponseHeadersEveryStagedRoute(t *testing.T) {
	for _, test := range configResponseStageCases() {
		t.Run(test.method+test.path, func(t *testing.T) {
			t.Setenv("CONTAIND_OPENVPN_DIR", t.TempDir())
			store := stageStore(t)
			server := NewServerWithEngine(store, nil, &stageEngine{mockEngine: &mockEngine{}})
			var rec *httptest.ResponseRecorder
			if test.path == "/ids/import" {
				rec = httptest.NewRecorder()
				server.ServeHTTP(rec, idsApplyRequest(t, "import"))
			} else {
				rec = requestStage(t, server, test.method, test.path, test.body)
			}
			if rec.Code < 200 || rec.Code >= 300 {
				t.Fatalf("stage failed: status=%d body=%s", rec.Code, rec.Body)
			}
			assertConfigResponseHeader(t, rec, "staged")
		})
	}
}

func TestConfigResponseHeadersEveryLifecycleRoute(t *testing.T) {
	for _, path := range []string{"/config/commit", "/config/commit_confirmed", "/config/confirm", "/config/rollback"} {
		t.Run(path, func(t *testing.T) {
			store := stageStore(t)
			ctx := context.Background()
			if err := store.SaveCandidate(ctx, config.DefaultConfig()); err != nil {
				t.Fatal(err)
			}
			if path == "/config/confirm" || path == "/config/rollback" {
				if err := store.CommitConfirmed(ctx, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			server := NewServerWithEngine(store, nil, &stageEngine{mockEngine: &mockEngine{}})
			rec := requestStage(t, server, "POST", path, map[string]int{"ttl_seconds": 3600})
			if rec.Code != http.StatusOK {
				t.Fatalf("lifecycle failed: %d %s", rec.Code, rec.Body)
			}
			assertConfigResponseHeader(t, rec, "committed")
		})
	}
}

func TestConfigResponseHeaderAbsentForPreviewAndErrors(t *testing.T) {
	for _, test := range []struct {
		method, path string
		body         any
		status       int
	}{
		{"POST", "/templates/ics/apply", map[string]any{"template": "modbus_read_only", "preview": true}, http.StatusOK},
		{"POST", "/firewall/rules", map[string]string{"action": "invalid"}, http.StatusBadRequest},
		{"PATCH", "/assets/missing", map[string]string{"name": "missing"}, http.StatusNotFound},
		{"POST", "/config/commit_confirmed", "invalid", http.StatusBadRequest},
		{"POST", "/config/rollback", nil, http.StatusBadRequest},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			rec := requestStage(t, NewServer(stageStore(t), nil), test.method, test.path, test.body)
			if rec.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, test.status, rec.Body)
			}
			assertConfigResponseHeader(t, rec, "")
		})
	}
}
