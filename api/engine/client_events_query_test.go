package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestClientEventsQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, filtered, err := dpevents.ParseQuery(r.URL.Query())
		if err != nil || !filtered || q.Session != "s" || q.Flow != "f" || q.Limit != 7 || q.Verdict != "drop_failed" {
			t.Errorf("query %s %v", r.URL, err)
		}
		if err := json.NewEncoder(w).Encode(dpevents.Page{Events: []dpevents.Event{{ID: 42}}, HistoryTruncated: true}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	p, err := NewHTTPClient(server.URL).QueryEvents(context.Background(), dpevents.Query{Session: "s", Flow: "f", Limit: 7, Verdict: "drop_failed"})
	if err != nil || len(p.Events) != 1 || p.Events[0].ID != 42 || !p.HistoryTruncated {
		t.Fatalf("%+v %v", p, err)
	}
}
