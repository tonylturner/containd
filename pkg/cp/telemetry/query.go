// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
)

type Query struct {
	Metric  wire.Metric
	Range   wire.Range
	Origin  wire.Origin
	Group   string
	Filters map[string]string
}

func ParseQuery(values url.Values) (Query, error) {
	q := Query{Metric: wire.Metric(values.Get("metric")), Range: wire.Range(values.Get("range")), Origin: wire.Origin(values.Get("origin")), Group: values.Get("group"), Filters: map[string]string{}}
	dims, ok := dimensions[q.Metric]
	if !ok {
		return q, fmt.Errorf("unknown metric")
	}
	if _, ok = wire.RangeResolution[q.Range]; !ok {
		return q, fmt.Errorf("unknown range")
	}
	if q.Origin != wire.OriginReal && q.Origin != wire.OriginDemo {
		return q, fmt.Errorf("unknown origin")
	}
	if q.Group != "" && !slices.Contains(dims, q.Group) {
		return q, fmt.Errorf("unknown group dimension")
	}
	for k, v := range values {
		if len(v) != 1 {
			return q, fmt.Errorf("repeated query parameter %s", k)
		}
		switch k {
		case "metric", "range", "origin", "group":
			continue
		}
		if !slices.Contains(dims, k) {
			return q, fmt.Errorf("unknown dimension %s", k)
		}
		q.Filters[k] = v[0]
	}
	return q, nil
}

// Query returns dense completed buckets. Gaps before admission or retention
// are explicit; no missing row is interpreted as an observed zero.
func (s *Store) Query(ctx context.Context, q Query, now time.Time) (wire.SeriesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := wire.RangeResolution[q.Range]
	if res == 0 {
		return wire.SeriesResponse{}, fmt.Errorf("invalid query range")
	}
	duration := map[wire.Range]time.Duration{wire.Range1h: time.Hour, wire.Range24h: 24 * time.Hour, wire.Range30d: 30 * 24 * time.Hour}[q.Range]
	to := now.UTC().Truncate(res)
	from := to.Add(-duration)
	out := wire.SeriesResponse{Metric: q.Metric, Unit: wire.MetricUnits[q.Metric], Origin: q.Origin, Range: q.Range, ResolutionSeconds: int(res / time.Second), From: from, To: to, Collector: s.state, Series: []wire.Series{}}
	out.Collector.Unavailable = q.unavailable(s.state.Unavailable)
	var covered, active int
	err := s.db.QueryRowContext(ctx, "SELECT covered,active FROM coverage WHERE metric=?", q.Metric).Scan(&covered, &active)
	if err != nil && err != sql.ErrNoRows {
		return out, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	out.RealCovered = covered != 0
	out.RealActive = active != 0
	var floor int64
	err = s.db.QueryRowContext(ctx, "SELECT t FROM floors WHERE resolution=?", out.ResolutionSeconds).Scan(&floor)
	if err != nil && err != sql.ErrNoRows {
		return out, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var oldest sql.NullInt64
	if err = s.db.QueryRowContext(ctx, "SELECT min(t) FROM buckets WHERE resolution=? AND t>=?", out.ResolutionSeconds, floor).Scan(&oldest); err != nil {
		return out, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if oldest.Valid {
		out.RetainedFrom = time.Unix(oldest.Int64, 0).UTC()
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,dims FROM series WHERE metric=? AND origin=? ORDER BY key", q.Metric, q.Origin)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	type member struct {
		id   int64
		dims map[string]string
	}
	members := []member{}
	for rows.Next() {
		var m member
		var raw string
		if err = rows.Scan(&m.id, &raw); err != nil {
			rows.Close()
			return out, err
		}
		if err = json.Unmarshal([]byte(raw), &m.dims); err != nil {
			rows.Close()
			return out, err
		}
		match := true
		for k, v := range q.Filters {
			if m.dims[k] != v {
				match = false
			}
		}
		if q.Group == "zone" && slices.Contains(dimensions[q.Metric], "role") && m.dims["role"] != "leaf" {
			match = false
		}
		if match {
			members = append(members, m)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	groups := map[string][]wire.Series{}
	for _, m := range members {
		stored, e := readPoints(ctx, s.db, m.id, out.ResolutionSeconds, from, to)
		if e != nil {
			return out, fmt.Errorf("%w: %v", ErrUnavailable, e)
		}
		series := wire.Series{Dims: m.dims, Points: make([]wire.Point, 0, int(duration/res))}
		for t := from; t.Before(to); t = t.Add(res) {
			p, exists := stored[t.Unix()]
			if !exists || t.Unix() < floor {
				p = wire.Point{T: t, Q: wire.QualityGap}
			}
			series.Points = append(series.Points, p)
		}
		if q.Group == "" {
			out.Series = append(out.Series, series)
		} else {
			groups[m.dims[q.Group]] = append(groups[m.dims[q.Group]], series)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(groups)) {
		members := groups[key]
		series := wire.Series{Dims: map[string]string{q.Group: key}, Points: make([]wire.Point, 0, int(duration/res))}
		for i := range members[0].Points {
			points := make([]wire.Point, 0, len(members))
			for _, member := range members {
				points = append(points, member.Points[i])
			}
			p, e := Combine(points, false, points[0].T)
			if e != nil {
				return out, e
			}
			series.Points = append(series.Points, p)
		}
		out.Series = append(out.Series, series)
	}
	return out, nil
}

// unavailable applies the query's selection before grouping. Match selectors,
// not retained members: a failed series may not have any history yet.
func (q Query) unavailable(entries []wire.SourceUnavailable) []wire.SourceUnavailable {
	source, _, _ := strings.Cut(string(q.Metric), ".")
	engineSourced := source != "service" && !(source == "events" && q.Filters["source"] == "services")
	var out []wire.SourceUnavailable
	for _, entry := range entries {
		if entry.Source != source && !(entry.Source == "engine" && engineSourced) {
			continue
		}
		if entry.Metric != "" && entry.Metric != q.Metric {
			continue
		}
		match := true
		for key, value := range q.Filters {
			if dim, exists := entry.Dims[key]; exists && dim != value {
				match = false
			}
		}
		if q.Group == "zone" && source == "iface" {
			if role, exists := entry.Dims["role"]; exists && role != "leaf" {
				match = false
			}
		}
		if match {
			out = append(out, entry)
		}
	}
	return cloneUnavailable(out)
}

// Total aggregates a returned window without concealing incomplete coverage.
func Total(resp wire.SeriesResponse) (uint64, bool, error) {
	var value uint64
	complete := len(resp.Series) > 0
	for _, series := range resp.Series {
		for _, p := range series.Points {
			complete = complete && p.Q == wire.QualityObserved
			if p.V != nil {
				var err error
				value, err = add(value, *p.V)
				if err != nil {
					return 0, false, err
				}
			}
		}
	}
	return value, complete, nil
}
