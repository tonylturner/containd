// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/cp/config"
	history "github.com/tonylturner/containd/pkg/cp/telemetry"
)

type conduitDemoHistory struct {
	real, demo wire.SeriesResponse
	origins    []wire.Origin
}

func (f *conduitDemoHistory) Query(_ context.Context, q history.Query, _ time.Time) (wire.SeriesResponse, error) {
	f.origins = append(f.origins, q.Origin)
	if q.Origin == wire.OriginDemo {
		return f.demo, nil
	}
	return f.real, nil
}
func TestConduitDemoPrecedence(t *testing.T) {
	value := uint64(23)
	covered := []wire.Series{{Points: []wire.Point{{V: &value, D: 10, Q: wire.QualityPartial}}}}
	gap := []wire.Series{{Points: []wire.Point{{Q: wire.QualityGap}}}}
	for _, tc := range []struct {
		name                     string
		real, demo               []wire.Series
		state, collector, source string
	}{
		{"demo", nil, covered, "demo", "running", ""},
		{"none", nil, nil, "none", "running", ""},
		{"old demo", nil, gap, "none", "running", ""},
		{"real gap", gap, covered, "unavailable", "running", ""},
		{"real", covered, covered, "measured", "running", ""},
		{"stalled", nil, covered, "unavailable", "stalled", ""},
		{"conduit unavailable", nil, covered, "unavailable", "running", "conduit"},
		{"engine unavailable", nil, covered, "unavailable", "running", "engine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &conduitDemoHistory{real: wire.SeriesResponse{Series: tc.real, Collector: wire.CollectorState{State: tc.collector}}, demo: wire.SeriesResponse{Series: tc.demo, Collector: wire.CollectorState{State: "running"}}}
			if tc.source != "" {
				f.real.Collector.Unavailable = []wire.SourceUnavailable{{Source: tc.source, Reason: "offline"}}
			}
			got := measureConduit(context.Background(), f, "a", "b")
			if got.State != tc.state {
				t.Fatal(got)
			}
			if got.State == "demo" && (got.Coverage != "recorded" || got.Bytes != "23" || got.Packets != "23" || got.Complete == nil || *got.Complete) {
				t.Fatal(got)
			}
			if got.State == "measured" && got.Coverage != "routed" {
				t.Fatal(got)
			}
			if len(tc.real) > 0 || tc.source != "" || tc.collector != "running" {
				for _, origin := range f.origins {
					if origin == wire.OriginDemo {
						t.Fatal("queried demo despite real/outage")
					}
				}
			}
		})
	}
}
func TestConduitEnforcementDisabledOutranksDemo(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataPlane.Enforcement = false
	cfg.Zones = []config.Zone{{Name: "lan"}, {Name: "wan"}}
	store := &mockStore{cfg: cfg}
	f := &conduitDemoHistory{}
	r := gin.New()
	r.GET("/", securityConduitsHandler(store, f))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"reason":"enforcement disabled"`) || len(f.origins) != 0 {
		t.Fatal(rec.Code, rec.Body, len(f.origins))
	}
}
