// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// countersEngine reports fixed rule counters, or err.
type countersEngine struct {
	*mockEngine
	counters dpengine.RuleCounters
	err      error
}

func (m *countersEngine) RuleCounters(context.Context) (dpengine.RuleCounters, error) {
	return m.counters, m.err
}

func TestRuleCountersRoute(t *testing.T) {
	excess := uint64(3)
	eng := &countersEngine{mockEngine: &mockEngine{}, counters: dpengine.RuleCounters{
		SnapshotVersion: "v9", Since: time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC),
		Rules: []enforce.RuleCount{{RuleID: "police", Action: rules.ActionRateLimit, Packets: 12, Bytes: 1200, ExcessDrops: &excess}},
	}}
	s := NewServerWithEngine(&mockStore{}, nil, eng)
	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/firewall/counters", nil))
		return rec
	}
	rec := get()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"since":"2026-10-26T08:00:00Z"`) ||
		!strings.Contains(rec.Body.String(), `"excessDrops":3`) {
		t.Fatalf("counters: %d %s", rec.Code, rec.Body)
	}
	eng.err = errors.New("rule counters unavailable: the last apply failed")
	if rec := get(); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "the last apply failed") {
		t.Fatalf("engine error: %d %s", rec.Code, rec.Body)
	}
	s = NewServerWithEngine(&mockStore{}, nil, &mockEngine{})
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/firewall/counters", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("engine without counters: %d", rec.Code)
	}
}
