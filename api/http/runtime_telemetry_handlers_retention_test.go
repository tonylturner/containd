// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

type retentionEngine struct {
	*runtimeMockEngine
	store *dpevents.Store
}

func (e retentionEngine) ListEvents(_ context.Context, limit int) ([]dpevents.Event, error) {
	return e.store.ListTelemetry(limit), nil
}

func retentionResponse(t *testing.T, s http.Handler, path string) []dpevents.Event {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, authedRequest(http.MethodGet, path, nil))
	var out []dpevents.Event
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
	}
	return out
}

func TestTelemetryRetainedDenyWithFullServices(t *testing.T) {
	store := dpevents.NewStore(4096)
	deny := store.Append(dpevents.Event{Kind: "firewall.rule.hit", Timestamp: time.Unix(1, 123), SrcIP: "192.0.2.10", DstIP: "192.0.2.20", DstPort: 2404, Attributes: map[string]any{"action": "DENY", "via": "nflog"}})
	newerDeny := deny
	newerDeny.ID = 0
	newerDeny.Timestamp = time.Unix(2, 0)
	newerDeny = store.Append(newerDeny)
	for i := 0; i < 5000; i++ {
		store.Append(dpevents.Event{Timestamp: time.Unix(int64(100+i), 0), FlowID: "now"})
	}
	svc := telemetryOnlyServices{}
	for i := 0; i < 2048; i++ {
		svc.events = append(svc.events, dpevents.Event{ID: 1<<63 + uint64(i), Kind: "service.test", Timestamp: time.Unix(int64(20000-i), 0)})
	}
	eng := retentionEngine{newRuntimeMockEngine(), store}
	s := NewServerWithEngineAndServices(&mockStore{}, nil, eng, svc, nil)
	for _, limit := range []int{1, 2, 3, 1024, 1025, 5000} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			out := retentionResponse(t, s, fmt.Sprintf("/api/v1/events?limit=%d", limit))
			if len(out) != limit {
				t.Fatalf("len %d want %d", len(out), limit)
			}
			seen := map[uint64]bool{}
			for i, e := range out {
				if seen[e.ID] {
					t.Fatalf("duplicate %d", e.ID)
				}
				seen[e.ID] = true
				if i > 0 && out[i-1].Timestamp.Before(e.Timestamp) {
					t.Fatal("not newest first")
				}
			}
			if !seen[newerDeny.ID] || (limit >= 2 && !seen[deny.ID]) {
				t.Fatalf("retained DENYs missing: %v", seen)
			}
			if limit > 2 && !seen[svc.events[0].ID] {
				t.Fatal("remaining slots must choose newest services")
			}
		})
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, authedRequest(http.MethodGet, fmt.Sprintf("/api/v1/events/%d", deny.ID), nil))
	var detail dpevents.Event
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &detail) != nil || detail.ID != deny.ID || !detail.Timestamp.Equal(deny.Timestamp) || detail.SrcIP != deny.SrcIP || detail.DstPort != 2404 || detail.Attributes["via"] != "nflog" {
		t.Fatalf("detail %d %s", rec.Code, rec.Body.String())
	}
}

func TestTelemetryMergeDedupeAndErrorVisibility(t *testing.T) {
	eng := newRuntimeMockEngine()
	deny := dpevents.Event{ID: 7, Kind: "firewall.rule.hit", Timestamp: time.Now().Add(time.Hour), Attributes: map[string]any{"action": "DENY"}}
	eng.eventsResp = []dpevents.Event{deny, deny}
	svc := telemetryOnlyServices{events: []dpevents.Event{deny, {ID: 8, Timestamp: time.Now()}}}
	s := NewServerWithEngineAndServices(&mockStore{}, nil, eng, svc, nil)
	if out := retentionResponse(t, s, "/api/v1/events?limit=3"); len(out) != 2 || out[0].ID != 7 || out[1].ID != 8 {
		t.Fatalf("deduped rows = %+v", out)
	}
	eng.eventsErr = errors.New("engine unreachable")
	if out := retentionResponse(t, s, "/api/v1/events?limit=1"); len(out) != 1 || out[0].Kind != "system.engine.telemetry_error" {
		t.Fatalf("error lost to DENY: %+v", out)
	}
}
