// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/audit"
)

func TestLabModeAuthRequiresAndAcceptsOptionalJWT(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_AUDITOR_TOKEN", "")
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	s := NewServerWithEngineAndServices(&mockStore{}, nil, nil, nil, us)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token in lab mode, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/auth/session", nil, tok+"broken")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid optional lab JWT, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/auth/session", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid optional lab JWT, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid /auth/session JSON: %v", err)
	}
	if resp["role"] != "admin" || resp["sessionId"] != "lab" {
		t.Fatalf("unexpected lab auth session response: %+v", resp)
	}
	userObj, ok := resp["user"].(map[string]any)
	if !ok || userObj["id"] != uid {
		t.Fatalf("expected lab session user payload, got %+v", resp["user"])
	}
}

func TestAuditHandlersListAndErrors(t *testing.T) {
	records := []audit.Record{
		{Actor: "alice", Action: "commit", Result: "success"},
		{Actor: "bob", Action: "login", Result: "success"},
	}
	auditStore := &mockAuditStore{records: records}
	s := NewServer(&mockStore{}, auditStore)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/audit?limit=5&offset=1", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /audit, got %d body=%s", rec.Code, rec.Body.String())
	}
	var got []audit.Record
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid /audit JSON: %v", err)
	}
	if len(got) != len(records) || got[0].Actor != "alice" {
		t.Fatalf("unexpected /audit records: %+v", got)
	}

	auditStore.err = assertErr("boom")
	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/audit?limit=bad&offset=-1", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 from /audit on store error, got %d body=%s", rec.Code, rec.Body.String())
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
