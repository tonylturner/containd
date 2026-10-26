// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/engine"
)

func learnMux(e *engine.Engine) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/learn", learnHandler(e))
	mux.HandleFunc("/internal/learn/profiles", learnProfilesHandler(e))
	mux.HandleFunc("/internal/learn/rules", learnRulesHandler(e))
	return mux
}

func TestLearnRoundTripThroughEngineClient(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(learnMux(e))
	defer srv.Close()
	client := engineapi.NewHTTPClient(srv.URL)
	ctx := context.Background()

	profiles, err := client.ListLearnProfiles(ctx)
	if err != nil || profiles == nil || len(profiles) != 0 {
		t.Fatalf("empty profiles = %#v, %v; want non-nil empty slice", profiles, err)
	}
	generated, err := client.GenerateLearnRules(ctx)
	if err != nil || generated == nil || len(generated) != 0 {
		t.Fatalf("empty rules = %#v, %v; want non-nil empty slice", generated, err)
	}

	e.Learner().RecordEvent("192.0.2.10", "192.0.2.20", dpi.Event{
		Proto:      "modbus",
		Timestamp:  time.Unix(1000, 0).UTC(),
		Attributes: map[string]any{"unit_id": uint8(1), "function_code": uint8(3), "address": "40001", "is_write": false},
	})
	profiles, err = client.ListLearnProfiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].Protocol != "modbus" || profiles[0].SourceIP != "192.0.2.10" || !profiles[0].UnitIDs[1] || !profiles[0].FunctionCodes[3] || profiles[0].PacketCount != 1 {
		t.Fatalf("profiles = %#v", profiles)
	}
	generated, err = client.GenerateLearnRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) != 1 || generated[0].ID != "learned-modbus-192.0.2.10-192.0.2.20" || generated[0].ICS.UnitID == nil || *generated[0].ICS.UnitID != 1 || len(generated[0].ICS.FunctionCode) != 1 || generated[0].ICS.FunctionCode[0] != 3 {
		t.Fatalf("generated rules = %#v", generated)
	}

	if err := client.ClearLearnData(ctx); err != nil {
		t.Fatal(err)
	}
	if left := e.Learner().Profiles(); len(left) != 0 {
		t.Fatalf("learner holds %d profiles after clear", len(left))
	}
}

func TestLearnHandlersRejectOtherMethodsAndMissingEngine(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/internal/learn"},
		{http.MethodPost, "/internal/learn/profiles"},
		{http.MethodDelete, "/internal/learn/rules"},
	} {
		w := httptest.NewRecorder()
		learnMux(e).ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s status = %d", tc.method, tc.path, w.Code)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodDelete, "/internal/learn"},
		{http.MethodGet, "/internal/learn/profiles"},
		{http.MethodGet, "/internal/learn/rules"},
	} {
		w := httptest.NewRecorder()
		learnMux(nil).ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Content-Type") != "application/json" || w.Body.String() != "{\"error\":\"learner unavailable\"}\n" {
			t.Fatalf("%s %s without engine: %d %q", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}
