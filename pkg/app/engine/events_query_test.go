// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestEngineEventsQuery(t *testing.T) {
	dp := newCountingDP(t)
	wanted := dp.Events().Append(dpevents.Event{Proto: "iec104", Kind: "ics.decision", Timestamp: time.Unix(1, 0), Attributes: map[string]any{"session_id": "incident", "decision": "deny"}})
	for i := 0; i < 5000; i++ {
		dp.Events().Append(dpevents.Event{Proto: "iec104", Kind: "response", Timestamp: time.Now()})
	}
	rec := httptest.NewRecorder()
	eventsHandler(dp.Engine).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/events?session=incident&decision=deny&limit=1", nil))
	var page dpevents.Page
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Events) != 1 || page.Events[0].ID != wanted.ID || !page.HistoryTruncated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	eventsHandler(dp.Engine).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/events?since=bad", nil))
	if rec.Code != 400 {
		t.Fatal(rec.Code)
	}
}
