// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

type stubStateLimitsClient struct{ err error }

func (p stubStateLimitsClient) StateLimits(context.Context) (limits.Snapshot, error) {
	return limits.Snapshot{Budget: limits.BudgetStatus{Limit: 67108864}}, p.err
}

func TestStateLimitsHandler(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client any
		status int
	}{
		{"live", stubStateLimitsClient{}, 200}, {"offline", stubStateLimitsClient{errors.New("offline")}, 503}, {"unsupported", struct{}{}, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/api/v1/diagnostics/state-limits", nil)
			stateLimitsHandler(tc.client)(c)
			if w.Code != tc.status {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
			if tc.status == 503 && w.Body.String() != `{"error":"engine state limits diagnostics unavailable"}` {
				t.Fatal(w.Body.String())
			}
		})
	}
}

type routedStateLimitsClient struct {
	*runtimeMockEngine
	stubStateLimitsClient
}

func TestStateLimitsRouteAuthentication(t *testing.T) {
	t.Setenv("CONTAIND_AUDITOR_TOKEN", "state-limits-reader")
	for _, tc := range []struct {
		name, token string
		client      EngineClient
		status      int
	}{
		{"anonymous", "", &routedStateLimitsClient{newRuntimeMockEngine(), stubStateLimitsClient{}}, 401},
		{"reader", "state-limits-reader", &routedStateLimitsClient{newRuntimeMockEngine(), stubStateLimitsClient{}}, 200},
		{"failed", "state-limits-reader", &routedStateLimitsClient{newRuntimeMockEngine(), stubStateLimitsClient{errors.New("private upstream failure")}}, 503},
		{"missing", "state-limits-reader", &mockEngine{}, 503},
		{"nil", "state-limits-reader", nil, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newTestServerWithEngine(&mockStore{}, nil, tc.client)
			req := httptest.NewRequest("GET", "/api/v1/diagnostics/state-limits", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			serveWithConfigRevision(t, server, rec, req)
			if rec.Code != tc.status {
				t.Fatalf("%d: %s", rec.Code, rec.Body)
			}
			if tc.status == 503 && rec.Body.String() != `{"error":"engine state limits diagnostics unavailable"}` {
				t.Fatal(rec.Body)
			}
		})
	}
}
