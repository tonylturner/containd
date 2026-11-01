// SPDX-License-Identifier: Apache-2.0

package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestClientEventsFeed(t *testing.T) {
	store := dpevents.NewStore(8)
	boundary := store.ReadFeed(dpevents.FeedRequest{TailOnly: true})
	store.Append(dpevents.Event{ID: 1<<63 + 1})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/events/forward" || r.URL.Query().Get("epoch") != boundary.Epoch || r.URL.Query().Get("after") != "0" || r.URL.Query().Get("limit") != "3" {
			t.Errorf("wrong feed request %s", r.URL)
		}
		if err := json.NewEncoder(w).Encode(store.ReadFeed(dpevents.FeedRequest{Epoch: boundary.Epoch, Limit: 3})); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	page, err := NewHTTPClient(server.URL).ReadEventFeed(context.Background(), dpevents.FeedRequest{Epoch: boundary.Epoch, Limit: 3})
	if err != nil || page.Epoch != boundary.Epoch || len(page.Records) != 1 || page.Records[0].Event.ID != 1<<63+1 {
		t.Fatalf("%+v %v", page, err)
	}
	server.Close()
	if _, err := NewHTTPClient(server.URL).ReadEventFeed(context.Background(), dpevents.FeedRequest{}); err == nil {
		t.Fatal("source outage must not become an empty page")
	}
}
