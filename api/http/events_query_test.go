package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func (m *runtimeMockEngine) QueryEvents(_ context.Context, q dpevents.Query) (dpevents.Page, error) {
	return dpevents.QueryPage(m.eventsResp, q, false, false), m.eventsErr
}
func (e retentionEngine) QueryEvents(_ context.Context, q dpevents.Query) (dpevents.Page, error) {
	return e.store.QueryTelemetry(q), e.eventsErr
}

func TestEventsQueryFiltersBeforeLimitAndMergedPagination(t *testing.T) {
	store := dpevents.NewStore(8)
	for i := 0; i < 4; i++ {
		store.Append(dpevents.Event{Kind: "wanted", FlowID: "f", Timestamp: time.Unix(100, 0), Attributes: map[string]any{"session_id": "s"}})
	}
	for i := 0; i < 4; i++ {
		store.Append(dpevents.Event{Kind: "noise", Timestamp: time.Unix(200, 0)})
	}
	svc := telemetryOnlyServices{events: []dpevents.Event{{ID: 1 << 63, Kind: "wanted", FlowID: "f", Timestamp: time.Unix(100, 0), Attributes: map[string]any{"session_id": "s"}}}}
	for i := 0; i < 3000; i++ {
		svc.events = append(svc.events, dpevents.Event{ID: 1<<63 + uint64(i+1), Kind: "service.noise", Timestamp: time.Unix(300, 0)})
	}
	eng := retentionEngine{newRuntimeMockEngine(), store}
	server := NewServerWithEngineAndServices(&mockStore{}, nil, eng, svc, nil)
	cursor := ""
	seen := map[uint64]bool{}
	for {
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/events?kind=wanted&session=s&flow=f&limit=2&cursor="+url.QueryEscape(cursor), nil))
		var page dpevents.Page
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		for _, e := range page.Events {
			if e.Kind != "wanted" || seen[e.ID] {
				t.Fatalf("wrong/duplicate row: %+v", e)
			}
			seen[e.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != 5 {
		t.Fatalf("lost merged rows %v", seen)
	}
	if out := retentionResponse(t, server, "/api/v1/events?limit=1"); len(out) != 1 {
		t.Fatal(out)
	}
	for _, raw := range []string{"since=bad", "cursor=bad", "limit=5001"} {
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/events?"+raw, nil))
		if rec.Code != 400 {
			t.Fatalf("%s status %d", raw, rec.Code)
		}
	}
	eng.eventsErr = fmt.Errorf("offline")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/events?session=missing", nil))
	var page dpevents.Page
	if json.Unmarshal(rec.Body.Bytes(), &page) != nil || page.EngineError != "offline" || !page.HistoryTruncated || len(page.Events) != 0 {
		t.Fatal(rec.Body.String())
	}
}

func TestEventsDetailBeyondLegacyPage(t *testing.T) {
	store := dpevents.NewStore(6000)
	oldest := store.Append(dpevents.Event{Kind: "request", Timestamp: time.Unix(1, 0)})
	for i := 0; i < 5500; i++ {
		store.Append(dpevents.Event{Kind: "ics.verdict", Proto: "iec104", Timestamp: time.Unix(int64(i+10), 0), Attributes: map[string]any{"session_id": fmt.Sprint(i / 32), "outcome": "drop_failed"}})
	}
	eng := retentionEngine{newRuntimeMockEngine(), store}
	server := NewServerWithEngineAndServices(&mockStore{}, nil, eng, nil, nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authedRequest(http.MethodGet, fmt.Sprintf("/api/v1/events/%d", oldest.ID), nil))
	var event dpevents.Event
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &event) != nil || event.ID != oldest.ID {
		t.Fatalf("detail lost retained row: %d %s", rec.Code, rec.Body.String())
	}
}
