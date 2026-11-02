// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	history "github.com/tonylturner/containd/pkg/cp/telemetry"
)

type fakeHistory struct {
	response wire.SeriesResponse
	err      error
	queries  []history.Query
}

func (f *fakeHistory) Query(_ context.Context, q history.Query, _ time.Time) (wire.SeriesResponse, error) {
	f.queries = append(f.queries, q)
	return f.response, f.err
}

func TestTelemetrySeriesHTTPValidationAndUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		store      TelemetryStore
		code       int
	}{
		{"unknown metric", "metric=unknown&range=1h&origin=real", nil, 400},
		{"unknown dimension", "metric=proto.bytes&range=1h&origin=real&zone=lan", nil, 400},
		{"unknown range", "metric=proto.bytes&range=2h&origin=real", nil, 400},
		{"unknown origin", "metric=proto.bytes&range=1h&origin=unknown", nil, 400},
		{"unavailable", "metric=proto.bytes&range=1h&origin=real", nil, 503},
		{"read error", "metric=proto.bytes&range=1h&origin=real", &fakeHistory{err: errors.New("disk failure")}, 503},
		{"overflow", "metric=proto.bytes&range=1h&origin=real", &fakeHistory{err: history.ErrOverflow}, 500},
		{"success", "metric=proto.bytes&range=1h&origin=real", &fakeHistory{}, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/", telemetrySeriesHandler(tc.store))
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?"+tc.path, nil))
			if rec.Code != tc.code {
				t.Fatal(rec.Code, rec.Body.String())
			}
		})
	}
}

func TestTelemetryDashboardRetainedCountsAndFailure(t *testing.T) {
	value := uint64(5)
	points := make([]wire.Point, 1440)
	start := time.Now().UTC().Truncate(time.Minute).Add(-24 * time.Hour)
	for i := range points {
		points[i] = wire.Point{T: start.Add(time.Duration(i) * time.Minute), V: &value, D: 60, Q: wire.QualityObserved}
	}
	f := &fakeHistory{response: wire.SeriesResponse{Series: []wire.Series{
		{Dims: map[string]string{"source": "engine"}, Points: points},
		{Dims: map[string]string{"source": "services"}, Points: append([]wire.Point(nil), points...)},
	}}}
	stats, err := collectDashboardEventStats(context.Background(), f)
	if err != nil || stats.Total != 14400 || !stats.Complete || stats.WindowSeconds != 86400 || len(f.queries) != 5 {
		t.Fatal(stats, err)
	}
	for _, q := range f.queries {
		if q.Range != wire.Range24h || q.Origin != wire.OriginReal {
			t.Fatal(q)
		}
	}
	f.response.Series[1].Points[0] = wire.Point{Q: wire.QualityGap}
	stats, err = collectDashboardEventStats(context.Background(), f)
	if err != nil || stats.Complete || stats.Total != 14395 {
		t.Fatal(stats, err)
	}
	f.err = errors.New("disk failure")
	stats, err = collectDashboardEventStats(context.Background(), f)
	if err == nil || stats != nil {
		t.Fatal(stats, err)
	}
}

func TestTelemetryConduitUnavailableAndMeasured(t *testing.T) {
	if got := measureConduit(context.Background(), nil, "a", "b"); got.State != "unavailable" || got.Reason == "" {
		t.Fatal(got)
	}
	f := &fakeHistory{response: wire.SeriesResponse{Collector: wire.CollectorState{State: "running"}}}
	if got := measureConduit(context.Background(), f, "a", "b"); got.State != "unavailable" {
		t.Fatal(got)
	}
	value := uint64(23)
	f.response.Series = []wire.Series{{Points: []wire.Point{{V: &value, D: 10, Q: wire.QualityPartial}}}}
	got := measureConduit(context.Background(), f, "a", "b")
	if got.State != "measured" || got.Bytes != "23" || got.Packets != "23" || got.Complete == nil || *got.Complete || got.Coverage != "routed" {
		t.Fatal(got)
	}
}
