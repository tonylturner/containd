// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// TestIdentityBindingRoutesStageCandidate: /identities edits the candidate's
// firewall.identityBindings, validated as configuration; the running
// configuration changes only on commit.
func TestIdentityBindingRoutesStageCandidate(t *testing.T) {
	ctx := context.Background()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Save(ctx, config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	s := NewServerWithEngineAndServices(store, nil, nil, nil, nil)
	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var r *http.Request
		if body == "" {
			r = authedRequest(method, path, nil)
		} else {
			r = authedRequest(method, path, bytes.NewBufferString(body))
			r.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		serveWithConfigRevision(t, s, rec, r)
		return rec
	}
	for _, tc := range []struct {
		method, path, body string
		status             int
		contains           string
	}{
		{http.MethodGet, "/api/v1/identities", "", http.StatusOK, `{"mappings":[]}`},
		{http.MethodPost, "/api/v1/identities", `{"ip":"bad","identities":["operator"]}`, http.StatusBadRequest, "invalid IP address"},
		{http.MethodPost, "/api/v1/identities", `{"ip":"10.0.0.10","identities":[" operator"]}`, http.StatusBadRequest, "surrounding spaces"},
		{http.MethodPost, "/api/v1/identities", `{"ip":"10.0.0.10"}`, http.StatusBadRequest, "needs 1 to 16 identities"},
		{http.MethodPost, "/api/v1/identities", `{"ip":"::ffff:10.0.0.10","identities":["operator","engineer"]}`, http.StatusOK, `{"ip":"10.0.0.10","identities":["operator","engineer"]}`},
		{http.MethodPost, "/api/v1/identities", `{"ip":"10.0.0.10","identities":["engineer"]}`, http.StatusOK, `"identities":["engineer"]`},
		{http.MethodPost, "/api/v1/identities", `{"ip":"2001:db8::7","identities":["vendor"]}`, http.StatusOK, `"2001:db8::7"`},
		{http.MethodGet, "/api/v1/identities", "", http.StatusOK, `{"mappings":[{"ip":"10.0.0.10","identities":["engineer"]},{"ip":"2001:db8::7","identities":["vendor"]}]}`},
		{http.MethodDelete, "/api/v1/identities/not-an-ip", "", http.StatusBadRequest, "invalid IP address"},
		{http.MethodDelete, "/api/v1/identities/10.0.0.99", "", http.StatusNotFound, "no identity binding for 10.0.0.99"},
		{http.MethodDelete, "/api/v1/identities/2001:db8::7", "", http.StatusOK, `{"deleted":"2001:db8::7"}`},
	} {
		rec := do(tc.method, tc.path, tc.body)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.contains) {
			t.Fatalf("%s %s %s: %d %s, want %d containing %s", tc.method, tc.path, tc.body, rec.Code, rec.Body.String(), tc.status, tc.contains)
		}
		if tc.method != http.MethodGet && tc.status == http.StatusOK && rec.Header().Get(configResponseHeader) != "staged" {
			t.Fatalf("%s %s: %s = %q, want staged", tc.method, tc.path, configResponseHeader, rec.Header().Get(configResponseHeader))
		}
	}
	running, err := store.Load(ctx)
	if err != nil || len(running.Firewall.IdentityBindings) != 0 {
		t.Fatalf("an identity edit reached the running config before commit: %+v, %v", running.Firewall.IdentityBindings, err)
	}
	if err := testCommit(store, ctx); err != nil {
		t.Fatal(err)
	}
	running, err = store.Load(ctx)
	if want := []config.IdentityBinding{{IP: "10.0.0.10", Identities: []string{"engineer"}}}; err != nil || !reflect.DeepEqual(running.Firewall.IdentityBindings, want) {
		t.Fatalf("committed bindings = %+v, %v; want %+v", running.Firewall.IdentityBindings, err, want)
	}
}

func TestTemplateAppendShadowWarning(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Firewall.Rules = []config.Rule{{ID: "earlier-deny", Action: config.ActionDeny}}
	cfg.DataPlane.NFQueueGroup = 101
	for _, path := range []string{"/templates/apply", "/templates/ics/apply"} {
		store := &mockStore{cfg: cfg}
		body := `{"name":"modbus-read-only","mode":"enforce"}`
		if path == "/templates/ics/apply" {
			body = `{"template":"modbus_read_only","mode":"enforce"}`
		}
		rec := httptest.NewRecorder()
		req := authedRequest("POST", "/api/v1"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		NewServer(store, nil).ServeHTTP(rec, withTestRevision(store, req))
		if rec.Code != 200 || !strings.Contains(strings.Join(rec.Header().Values("X-Containd-Warnings"), " "), "earlier-deny") || store.cfg.Firewall.Rules[0].ID != "earlier-deny" {
			t.Fatalf("%s: response=%d %s headers=%v", path, rec.Code, rec.Body, rec.Header())
		}
	}
}
