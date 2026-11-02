// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/dp/telemetry"
)

func TestTelemetryCountersHandler(t *testing.T) {
	handler := telemetryCountersHandler(telemetry.Collector{BootID: engineBootID})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/telemetry/counters", nil))
	var snapshot wire.CounterSnapshot
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &snapshot) != nil || snapshot.BootID != engineBootID || len(snapshot.Unavailable) != 5 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/telemetry/counters", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal(rec.Code)
	}
}
