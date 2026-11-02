// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/services"
)

type countedAVEngine struct{ EngineClient }

func (countedAVEngine) AVStatus(context.Context) (map[string]any, error) {
	return map[string]any{"count": 7, "errors_count": 2}, nil
}

func TestServicesStatusLifetimeCountsOnly(t *testing.T) {
	manager := services.NewManager(services.ManagerOptions{BaseDir: t.TempDir()})
	manager.IncrementServiceMetric("dns", 3)
	router := gin.New()
	router.GET("/", getServicesStatusHandler(manager, countedAVEngine{}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for name, raw := range out {
		if name == "faults" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatal(name, err)
		}
		for _, removed := range []string{"sparkline", "errors_sparkline", "rate_per_min", "errors_rate_per_min"} {
			if _, exists := entry[removed]; exists {
				t.Fatal(name, removed)
			}
		}
		if _, exists := entry["count"]; !exists {
			t.Fatal(name, "missing count")
		}
		if _, exists := entry["errors_count"]; !exists {
			t.Fatal(name, "missing errors_count")
		}
	}
	var av map[string]any
	if err := json.Unmarshal(out["av"], &av); err != nil {
		t.Fatal(err)
	}
	if av["count"] != float64(7) || av["errors_count"] != float64(2) {
		t.Fatal(av)
	}
}
