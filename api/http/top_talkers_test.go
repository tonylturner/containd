// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/stats"
)

func TestTopTalkersObjectAndClamp(t *testing.T) {
	eng := newRuntimeMockEngine()
	eng.topTalkersResp = stats.TopTalkers{Semantics: "recent", Limit: 0, Retained: 5, Since: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Complete: true, Rows: []stats.FlowStats{}}
	s := newTestServerWithEngine(&mockStore{}, nil, eng)
	for _, tc := range []struct {
		n    string
		want int
	}{{"", 10}, {"bad", 10}, {"0", 1}, {"-10", 1}, {"3", 3}, {"1001", 1000}} {
		rec := httptest.NewRecorder()
		req := authedRequest(http.MethodGet, "/api/v1/stats/top-talkers?n="+tc.n, nil)
		serveWithConfigRevision(t, s, rec, req)
		var got stats.TopTalkers
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 200 || eng.topTalkersN != tc.want || got.Semantics != "recent" || got.Retained != 5 || !got.Since.Equal(eng.topTalkersResp.Since) || !got.Complete || got.Rows == nil {
			t.Fatalf("query %q -> %d, %+v status %d", tc.n, eng.topTalkersN, got, rec.Code)
		}
	}
}
