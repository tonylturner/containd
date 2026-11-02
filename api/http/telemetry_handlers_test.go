// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	history "github.com/tonylturner/containd/pkg/cp/telemetry"
)

type unavailableCounterReader struct{}

func (unavailableCounterReader) TelemetryCounters(context.Context) (wire.CounterSnapshot, error) {
	return wire.CounterSnapshot{Unavailable: []wire.SourceUnavailable{
		{Source: "events", Dims: map[string]string{"source": "engine"}, Reason: "engine events unavailable"},
		{Source: "service", Dims: map[string]string{"service": "dns"}, Reason: "DNS meter unavailable"},
	}}, errors.New("engine offline")
}

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

func TestTelemetryConduitCurrentOutageOutranksHistory(t *testing.T) {
	value := uint64(23)
	for _, tc := range []struct {
		source, reason string
	}{
		{"conduit", "enforcement disabled"},
		{"engine", "engine offline"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			f := &fakeHistory{response: wire.SeriesResponse{
				Collector: wire.CollectorState{State: "running", Unavailable: []wire.SourceUnavailable{{Source: tc.source, Reason: tc.reason}}},
				Series: []wire.Series{{Points: []wire.Point{
					{V: &value, D: 10, Q: wire.QualityObserved}, {Q: wire.QualityGap},
				}}},
			}}
			got := measureConduit(context.Background(), f, "lan", "wan")
			if got.State != "unavailable" || got.Reason != tc.reason || got.Bytes != "" || got.Packets != "" {
				t.Fatal("outage hidden by retained traffic", got)
			}
			f.response.Collector.Unavailable = nil
			if got := measureConduit(context.Background(), f, "lan", "wan"); got.State != "measured" || got.Bytes != "23" {
				t.Fatal("recovery failed", got)
			}
		})
	}
}

func TestTelemetrySeriesHTTPCurrentUnavailableSelection(t *testing.T) {
	store, err := history.Open(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := history.NewSampler(store, unavailableCounterReader{}).Tick(context.Background(), time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/", telemetrySeriesHandler(store))
	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"metric=events.total", []string{"engine events unavailable", "engine offline"}},
		{"metric=events.total&source=services", nil},
		{"metric=service.events&service=dns", []string{"DNS meter unavailable"}},
		{"metric=service.events&service=ntp", nil},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?range=1h&origin=real&"+tc.query, nil))
			if rec.Code != http.StatusOK {
				t.Fatal(rec.Code, rec.Body.String())
			}
			var got wire.SeriesResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Collector.Unavailable) != len(tc.want) {
				t.Fatal(got.Collector)
			}
			for i, reason := range tc.want {
				if got.Collector.Unavailable[i].Reason != reason {
					t.Fatal(got.Collector)
				}
			}
		})
	}
}
