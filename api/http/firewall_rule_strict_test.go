// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const unknownRuleKeyConfig = `{
	"firewall":{"defaultAction":"DENY","rules":[{"id":"strict-rule","action":"ALLOW","state":["on"]}]}
}`

func strictRuleRequest(t *testing.T, server http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := authedRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	server.ServeHTTP(rec, req)
	return rec
}

func assertUnknownRule400(t *testing.T, rec *httptest.ResponseRecorder, detailed bool, ruleID string) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if detailed && (!strings.Contains(rec.Body.String(), `unknown key \"state\"`) ||
		!strings.Contains(rec.Body.String(), `id \"`+ruleID+`\"`)) {
		t.Fatalf("body = %s, want unknown key and rule ID", rec.Body.String())
	}
}

func TestUnknownRuleKeysRejectedByConfigIngestion(t *testing.T) {
	t.Run("running config", func(t *testing.T) {
		store := &mockStore{}
		rec := strictRuleRequest(t, NewServer(store, nil), http.MethodPost, "/api/v1/config", unknownRuleKeyConfig)
		assertUnknownRule400(t, rec, true, "strict-rule")
		if store.calls != 0 {
			t.Fatalf("Save calls = %d, want 0", store.calls)
		}
	})

	t.Run("candidate config", func(t *testing.T) {
		store := &mockStore{}
		rec := strictRuleRequest(t, NewServer(store, nil), http.MethodPost, "/api/v1/config/candidate", unknownRuleKeyConfig)
		assertUnknownRule400(t, rec, true, "strict-rule")
		if store.calls != 0 {
			t.Fatalf("Save calls = %d, want 0", store.calls)
		}
	})

	t.Run("import", func(t *testing.T) {
		store := &mockStore{}
		rec := strictRuleRequest(t, NewServer(store, nil), http.MethodPost, "/api/v1/config/import", unknownRuleKeyConfig)
		assertUnknownRule400(t, rec, true, "strict-rule")
		if store.calls != 0 {
			t.Fatalf("Save calls = %d, want 0", store.calls)
		}
	})

	t.Run("rule patch", func(t *testing.T) {
		store := iecPatchStore(config.ICSPredicate{Protocol: "iec104"})
		rec := strictRuleRequest(t, NewServer(store, nil), http.MethodPatch, "/api/v1/firewall/rules/r1", `{"state":["on"]}`)
		assertUnknownRule400(t, rec, true, "r1")
		if store.calls != 0 {
			t.Fatalf("Save calls = %d, want 0", store.calls)
		}
	})

	t.Run("create rule", func(t *testing.T) {
		store := &mockStore{cfg: config.DefaultConfig()}
		rec := strictRuleRequest(t, NewServer(store, nil), http.MethodPost, "/api/v1/firewall/rules",
			`{"id":"strict-rule","action":"ALLOW","state":["on"]}`)
		assertUnknownRule400(t, rec, true, "strict-rule")
		if store.calls != 0 {
			t.Fatalf("Save calls = %d, want 0", store.calls)
		}
	})

	t.Run("create ICS rule", func(t *testing.T) {
		store := &mockStore{cfg: config.DefaultConfig()}
		rec := strictRuleRequest(t, NewServer(store, nil), http.MethodPost, "/api/v1/firewall/ics-rules",
			`{"id":"strict-rule","action":"ALLOW","ics":{"protocol":"iec104"},"state":["on"]}`)
		assertUnknownRule400(t, rec, true, "strict-rule")
		if store.calls != 0 {
			t.Fatalf("Save calls = %d, want 0", store.calls)
		}
	})

	t.Run("replace ICS rule", func(t *testing.T) {
		store := iecPatchStore(config.ICSPredicate{Protocol: "iec104"})
		rec := strictRuleRequest(t, NewServer(store, nil), http.MethodPatch, "/api/v1/firewall/ics-rules/r1",
			`{"id":"r1","action":"ALLOW","ics":{"protocol":"iec104"},"state":["on"]}`)
		assertUnknownRule400(t, rec, true, "r1")
		if store.calls != 0 {
			t.Fatalf("Save calls = %d, want 0", store.calls)
		}
	})
}

func TestCommitRejectsPersistedCandidateWithUnknownRuleKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "config.db")
	store, err := config.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open config store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open config database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO configs (key, data, updated_at) VALUES (?, ?, ?)`,
		"candidate", unknownRuleKeyConfig, 1); err != nil {
		t.Fatalf("seed candidate config: %v", err)
	}

	rec := strictRuleRequest(t, NewServer(store, nil), http.MethodPost, "/api/v1/config/commit", "")
	assertUnknownRule400(t, rec, true, "strict-rule")
}
