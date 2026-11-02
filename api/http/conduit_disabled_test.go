// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestTelemetryConduitDisabledRetainedHistory(t *testing.T) {
	count := uint64(23)
	now := time.Now().UTC().Truncate(10 * time.Second)
	h := &fakeHistory{response: wire.SeriesResponse{
		Collector: wire.CollectorState{State: "running"},
		Series: []wire.Series{{Points: []wire.Point{
			{T: now.Add(-20 * time.Second), V: &count, D: 10, Q: wire.QualityObserved},
			{T: now.Add(-10 * time.Second), Q: wire.QualityGap},
		}}},
	}}
	cfg := &config.Config{
		System: config.SystemConfig{Hostname: "containd"},
		Zones:  []config.Zone{{Name: "lan"}, {Name: "wan"}},
	}
	cfg.DataPlane.Enforcement = false
	router := gin.New()
	router.GET("/", securityConduitsHandler(&mockStore{cfg: cfg}, h))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatal(recorder.Code, recorder.Body.String())
	}
	var got []conduitResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	traffic := requireConduit(t, got, "lan", "wan").Traffic
	if traffic.State != "unavailable" || traffic.Reason != "enforcement disabled" {
		t.Fatalf("disabled enforcement must outrank retained coverage; got %+v", traffic)
	}
}
