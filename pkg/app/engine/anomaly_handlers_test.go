// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/engine"
)

// recordMalformed feeds n decoder errors through the engine's detector, each
// producing one malformed_frame anomaly.
func recordMalformed(t *testing.T, e *engine.Engine, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		ev := dpi.Event{Proto: "dnp3", Timestamp: time.Unix(int64(1000+i), 0).UTC(), Attributes: map[string]any{"error": fmt.Sprintf("frame %d", i)}}
		if got := e.AnomalyDetector().Check("192.0.2.10", "192.0.2.20", ev); len(got) != 1 {
			t.Fatalf("Check recorded %d anomalies, want 1", len(got))
		}
	}
}

func TestAnomaliesRoundTripThroughEngineClient(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(anomaliesHandler(e))
	defer srv.Close()
	client := engineapi.NewHTTPClient(srv.URL)
	ctx := context.Background()

	empty, err := client.ListAnomalies(ctx, 5)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty list = %#v, %v; want non-nil empty slice", empty, err)
	}

	recordMalformed(t, e, 3)
	got, err := client.ListAnomalies(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Type != "malformed_frame" || got[0].Message != "Malformed frame: frame 2" || got[1].Message != "Malformed frame: frame 1" {
		t.Fatalf("limited list = %#v; want the two newest anomalies, newest first", got)
	}
	if got[0].SourceIP != "192.0.2.10" || got[0].DestIP != "192.0.2.20" || !got[0].Timestamp.Equal(time.Unix(1002, 0)) {
		t.Fatalf("anomaly fields = %#v", got[0])
	}

	if err := client.ClearAnomalies(ctx); err != nil {
		t.Fatal(err)
	}
	if after := e.AnomalyDetector().Anomalies(0); len(after) != 0 {
		t.Fatalf("detector holds %d anomalies after clear", len(after))
	}
}

func TestAnomaliesLimitBounds(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	recordMalformed(t, e, defaultAnomalyLimit+1)
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", defaultAnomalyLimit},
		{"?limit=7", 7},
		{"?limit=0", defaultAnomalyLimit},
		{"?limit=-1", defaultAnomalyLimit},
		{"?limit=bogus", defaultAnomalyLimit},
		{fmt.Sprintf("?limit=%d", maxAnomalyLimit+1), defaultAnomalyLimit},
		{fmt.Sprintf("?limit=%d", maxAnomalyLimit), defaultAnomalyLimit + 1},
	} {
		w := httptest.NewRecorder()
		anomaliesHandler(e)(w, httptest.NewRequest(http.MethodGet, "/internal/anomalies"+tc.query, nil))
		var list []anomaly.Anomaly
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
			t.Fatalf("limit%s: decode: %v", tc.query, err)
		}
		if w.Code != http.StatusOK || len(list) != tc.want {
			t.Fatalf("limit%s: status %d, %d anomalies; want 200 and %d", tc.query, w.Code, len(list), tc.want)
		}
	}
}

func TestAnomaliesHandlerRejectsOtherMethodsAndMissingEngine(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	anomaliesHandler(e)(w, httptest.NewRequest(http.MethodPost, "/internal/anomalies", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", w.Code)
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		w := httptest.NewRecorder()
		anomaliesHandler(nil)(w, httptest.NewRequest(method, "/internal/anomalies", nil))
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Content-Type") != "application/json" || w.Body.String() != "{\"error\":\"anomaly detector unavailable\"}\n" {
			t.Fatalf("%s without engine: %d %q", method, w.Code, w.Body.String())
		}
	}
}
