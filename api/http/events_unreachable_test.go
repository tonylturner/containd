// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestEventsReportsUnreachableEngineWithoutOtherEvents(t *testing.T) {
	eng := newRuntimeMockEngine()
	eng.eventsErr = errors.New("dial tcp 127.0.0.1:8081: connection refused")
	s := NewServerWithEngine(&mockStore{}, nil, eng)

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/events", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got []dpevents.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not a bare event array: %v", err)
	}
	if len(got) != 1 || got[0].Kind != "system.engine.telemetry_error" || got[0].Attributes["error"] != eng.eventsErr.Error() {
		t.Fatalf("events = %+v, want one telemetry_error event", got)
	}
}
