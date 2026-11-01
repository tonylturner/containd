// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type shadowEngine struct {
	*mockEngine
	counters dpengine.ShadowCounters
	err      error
}

func (e *shadowEngine) ShadowCounters(context.Context) (dpengine.ShadowCounters, error) {
	return e.counters, e.err
}

func TestShadowCountersRoute(t *testing.T) {
	since := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	eng := &shadowEngine{mockEngine: &mockEngine{}, counters: dpengine.ShadowCounters{Available: true, SnapshotVersion: "applied", Since: &since, Unit: "messages", Rules: []dpengine.ShadowRuleCount{{RuleID: "trial", ShadowMatches: 12, WouldAllow: 10, WouldDeny: 2}}}}
	s := NewServerWithEngine(&mockStore{}, nil, eng)
	get := func(authed bool) *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/firewall/shadow-counters", nil)
		if authed {
			req = authedRequest(http.MethodGet, req.URL.String(), nil)
		}
		serveWithConfigRevision(t, s, r, req)
		return r
	}
	if r := get(false); r.Code != http.StatusUnauthorized {
		t.Fatalf("unprotected: %d", r.Code)
	}
	if r := get(true); r.Code != 200 || !strings.Contains(r.Body.String(), `"wouldDeny":2`) || !strings.Contains(r.Body.String(), `"unit":"messages"`) {
		t.Fatal(r.Code, r.Body)
	}
	eng.err = errors.New("engine unreachable")
	if r := get(true); r.Code != 200 || !strings.Contains(r.Body.String(), `"available":false`) || strings.Contains(r.Body.String(), `"rules"`) {
		t.Fatal(r.Code, r.Body)
	}
	eng.err = nil
	eng.counters = dpengine.ShadowCounters{Available: true, SnapshotVersion: "empty", Since: &since, Unit: "messages"}
	if r := get(true); !strings.Contains(r.Body.String(), `"rules":[]`) {
		t.Fatal(r.Body)
	}
}
