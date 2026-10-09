// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

type healthMockEngine struct {
	*mockEngine
	st  dpengine.IEC104Enforcement
	err error
}

func (m *healthMockEngine) IEC104Enforcement(context.Context) (dpengine.IEC104Enforcement, error) {
	return m.st, m.err
}

func healthBody(t *testing.T, engine EngineClient) (int, map[string]any) {
	t.Helper()
	s := NewServerWithEngine(&mockStore{}, nil, engine)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/health", nil)
	s.ServeHTTP(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return rec.Code, body
}

func TestHealthReportsIEC104Enforcement(t *testing.T) {
	cases := []struct {
		name   string
		engine EngineClient
		want   map[string]any
	}{
		{"no engine", nil, map[string]any{"active": false, "healthy": false, "reason": "engine unreachable"}},
		{"engine error", &healthMockEngine{mockEngine: &mockEngine{}, err: errors.New("connection refused")},
			map[string]any{"active": false, "healthy": false, "reason": "engine unreachable"}},
		{"engine unhealthy", &healthMockEngine{mockEngine: &mockEngine{}, st: dpengine.IEC104Enforcement{Active: true, Reason: "reset injector unavailable"}},
			map[string]any{"active": true, "healthy": false, "reason": "reset injector unavailable"}},
		{"inactive", &healthMockEngine{mockEngine: &mockEngine{}, st: dpengine.IEC104Enforcement{Healthy: true}},
			map[string]any{"active": false, "healthy": true, "reason": ""}},
	}
	for _, c := range cases {
		code, body := healthBody(t, c.engine)
		if code != http.StatusOK || body["status"] != "ok" {
			t.Fatalf("%s: liveness = %d %v", c.name, code, body)
		}
		got, _ := body["iec104Enforcement"].(map[string]any)
		for k, v := range c.want {
			if got[k] != v {
				t.Fatalf("%s: iec104Enforcement = %v, want %v", c.name, got, c.want)
			}
		}
	}
}
