// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestEngineEventsFeed(t *testing.T) {
	dp := newCountingDP(t)
	dp.Events().Append(dpevents.Event{ID: 1<<63 + 1})
	rec := httptest.NewRecorder()
	eventsFeedHandler(dp.Engine).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/events/forward?after=0&limit=1", nil))
	var page dpevents.FeedPage
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil || page.Tail != 1 || len(page.Records) != 1 || page.Records[0].Event.ID != 1<<63+1 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	for _, query := range []string{"after=bad&limit=1", "after=0&limit=bad", "after=0&limit=5001"} {
		rec := httptest.NewRecorder()
		eventsFeedHandler(dp.Engine).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/events/forward?"+query, nil))
		if rec.Code != 400 {
			t.Fatal(query, rec.Code)
		}
	}
}
