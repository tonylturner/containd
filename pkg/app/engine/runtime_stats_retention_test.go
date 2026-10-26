// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestTelemetryDenySurvivesRebuildAndWrap(t *testing.T) {
	dp := newCountingDP(t)
	h := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{dpEngine: dp.Engine, logger: zap.NewNop().Sugar()})
	deny := dp.Events().Append(dpevents.Event{Kind: "firewall.rule.hit", Timestamp: time.Unix(1, 123), SrcIP: "192.0.2.1", DstIP: "192.0.2.2", DstPort: 2404, Attributes: map[string]any{"action": "DENY"}})
	postConfig(t, h, `{"dpiEnabled":false}`)
	dp.waitStart(t)
	postConfig(t, h, `{"dpiEnabled":true}`)
	dp.waitStart(t)
	for i := 0; i < 5000; i++ {
		dp.Events().Append(dpevents.Event{Timestamp: time.Now(), FlowID: "new"})
	}
	rec := httptest.NewRecorder()
	eventsHandler(dp.Engine).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/events?limit=1", nil))
	var got []dpevents.Event
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || len(got) != 1 || got[0].ID != deny.ID || !got[0].Timestamp.Equal(deny.Timestamp) || got[0].SrcIP != deny.SrcIP || got[0].DstPort != 2404 {
		t.Fatalf("after rebuild/wrap: %d %s", rec.Code, rec.Body.String())
	}
	if dp.reconfigs.Load() != 2 {
		t.Fatalf("rebuild count %d", dp.reconfigs.Load())
	}
}
