// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/common/evidence"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type evidenceFailingStore struct {
	audit.ObservableStore
	err      error
	attempts []audit.Record
}

func (s *evidenceFailingStore) Add(ctx context.Context, r audit.Record) error {
	s.attempts = append(s.attempts, r)
	if s.err != nil {
		return s.err
	}
	return s.ObservableStore.Add(ctx, r)
}
func newEvidenceStore(t *testing.T) (*audit.ObservedStore, *evidenceFailingStore) {
	t.Helper()
	raw, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	backend := &evidenceFailingStore{ObservableStore: raw}
	return audit.NewObservedStore(backend), backend
}

type evidenceServices struct{ statuses []evidence.ForwardStatus }

func (s evidenceServices) Apply(context.Context, config.ServicesConfig) error { return nil }
func (s evidenceServices) ForwardStatus() []evidence.ForwardStatus            { return s.statuses }

func TestEvidenceStatusAuthenticationAndNoCollector(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "0")
	t.Setenv("CONTAIND_ADMIN_TOKEN", "admin-status-test")
	t.Setenv("CONTAIND_AUDITOR_TOKEN", "view-status-test")
	t.Setenv("CONTAIND_JWT_SECRET", "")
	observed, backend := newEvidenceStore(t)
	backend.err = errors.New("password=secret /private/audit.db")
	if err := observed.Add(context.Background(), audit.Record{}); err == nil {
		t.Fatal("expected failure")
	}
	server := NewServer(&mockStore{}, observed)
	for _, tc := range []struct {
		token string
		code  int
	}{{"", 401}, {"wrong", 401}, {"view-status-test", 200}, {"admin-status-test", 200}} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/status", nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
		}
		if tc.code != 200 {
			continue
		}
		var status evidence.Status
		if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Audit.State != evidence.StateDegraded || status.Audit.Failures != 1 || status.Forwarding == nil || len(status.Forwarding) != 0 {
			t.Fatalf("%+v", status)
		}
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	var health map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if string(health["evidence"]) != `{"state":"degraded"}` {
		t.Fatalf("health leaks or hides evidence: %s", health["evidence"])
	}
}

func TestEvidenceForwardingAndHealthStates(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "0")
	t.Setenv("CONTAIND_ADMIN_TOKEN", "status-test-token")
	t.Setenv("CONTAIND_JWT_SECRET", "")
	for _, state := range []evidence.State{evidence.StateOK, evidence.StateRecovered, evidence.StateUnknown, evidence.StateDegraded} {
		t.Run(string(state), func(t *testing.T) {
			observed, _ := newEvidenceStore(t)
			services := evidenceServices{statuses: []evidence.ForwardStatus{{Destination: "tcp://private-collector:514", Source: evidence.SourceEngine, State: state, LastError: "private forwarding error"}}}
			status := readEvidence(observed, services)
			if len(status.Forwarding) != 1 || status.Forwarding[0].Destination != "tcp://private-collector:514" || evidenceHealth(status) != state {
				t.Fatalf("%+v", status)
			}
			rec := httptest.NewRecorder()
			server := NewServerWithEngineAndServices(&mockStore{}, observed, nil, services, nil)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/status", nil)
			req.Header.Set("Authorization", "Bearer status-test-token")
			server.ServeHTTP(rec, req)
			var response evidence.Status
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if rec.Code != 200 || len(response.Forwarding) != 1 || response.Forwarding[0].Destination != services.statuses[0].Destination {
				t.Fatalf("forwarding endpoint: %d %s", rec.Code, rec.Body)
			}
			rec = httptest.NewRecorder()
			server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
			var health struct {
				Evidence map[string]any `json:"evidence"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
				t.Fatal(err)
			}
			if len(health.Evidence) != 1 || health.Evidence["state"] != string(state) {
				t.Fatalf("%v", health.Evidence)
			}
		})
	}
	if s := readEvidence(&mockAuditStore{}); s.Audit.State != evidence.StateUnknown || evidenceHealth(s) != evidence.StateUnknown {
		t.Fatalf("unobserved: %+v", s)
	}
	for _, tc := range []struct{ a, b, w evidence.State }{
		{evidence.StateUnknown, evidence.StateDegraded, evidence.StateDegraded},
		{evidence.StateRecovered, evidence.StateUnknown, evidence.StateUnknown},
		{evidence.StateDegraded, evidence.StateOK, evidence.StateDegraded},
	} {
		if got := evidenceHealth(evidence.Status{Audit: evidence.AuditStatus{State: tc.a}, Forwarding: []evidence.ForwardStatus{{State: tc.b}}}); got != tc.w {
			t.Fatalf("%s/%s=%s", tc.a, tc.b, got)
		}
	}
}
