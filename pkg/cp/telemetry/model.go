// SPDX-License-Identifier: Apache-2.0

// Package telemetry collects and retains operational counter history.
package telemetry

import (
	"encoding/json"
	"errors"
	"math"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
)

var ErrOverflow = errors.New("telemetry counter sum overflow")
var ErrUnavailable = errors.New("telemetry store unavailable")

const Resolution = 10 * time.Second

var dimensions = map[wire.Metric][]string{
	wire.IfaceRxBytes: {"interface", "zone", "role"}, wire.IfaceTxBytes: {"interface", "zone", "role"},
	wire.IfaceRxPackets: {"interface", "zone", "role"}, wire.IfaceTxPackets: {"interface", "zone", "role"},
	wire.ConduitBytes: {"from", "to"}, wire.ConduitPackets: {"from", "to"},
	wire.ProtoBytes: {"protocol"}, wire.ProtoPackets: {"protocol"},
	wire.EventsTotal: {"source"}, wire.EventsClass: {"source", "class"},
	wire.ServiceEvents: {"service"}, wire.ServiceErrors: {"service"},
	wire.AVScans: {}, wire.AVScanErrors: {}, wire.AVDetections: {},
}

func identity(s wire.CounterSample) string {
	b, _ := json.Marshal(s.Dims)
	if len(s.Dims) == 0 {
		b = []byte("{}")
	}
	origin := s.Origin
	if origin == "" {
		origin = wire.OriginReal
	}
	return string(s.Metric) + "/" + string(origin) + "/" + string(b)
}

func add(a, b uint64) (uint64, error) {
	if math.MaxUint64-a < b {
		return 0, ErrOverflow
	}
	return a + b, nil
}

// Combine applies either temporal roll-up or cross-series grouping quality.
// Missing members must be represented by gap points.
func Combine(points []wire.Point, temporal bool, t time.Time) (wire.Point, error) {
	out := wire.Point{T: t, Q: wire.QualityGap}
	var value uint64
	covered, observed, reset, gap := 0, true, false, false
	commonDuration := true
	for _, p := range points {
		if p.V == nil {
			gap = true
			observed = false
			continue
		}
		var err error
		value, err = add(value, *p.V)
		if err != nil {
			return out, err
		}
		covered++
		observed = observed && p.Q == wire.QualityObserved
		reset = reset || p.Q == wire.QualityReset
		gap = gap || p.Q == wire.QualityGap || p.Q == wire.QualityPartial
		if temporal {
			out.D += p.D
		} else if covered == 1 {
			out.D = p.D
		} else if p.D != out.D {
			commonDuration = false
		}
	}
	if covered == 0 {
		return out, nil
	}
	out.V = &value
	switch {
	case !temporal && !commonDuration:
		out.D = 0
		out.Q = wire.QualityPartial
	case reset && (temporal || !gap):
		out.Q = wire.QualityReset
	case observed:
		out.Q = wire.QualityObserved
	default:
		out.Q = wire.QualityPartial
	}
	return out, nil
}

type previous struct {
	sample wire.CounterSample
	wall   time.Time
	mono   time.Duration
}

// delta never distributes counts across unobserved buckets. Exact aligned
// intervals cover the preceding bucket. Other intervals are attributed to the
// sample's bucket, which remains excluded from queries until it closes.
func delta(prev previous, sample wire.CounterSample, wall time.Time, mono time.Duration) wire.Point {
	end := wall.Truncate(Resolution)
	p := wire.Point{T: end, Q: wire.QualityGap}
	elapsed := mono - prev.mono
	wallElapsed := wall.Sub(prev.wall)
	skew := wallElapsed - elapsed
	if elapsed <= 0 || elapsed > 15*time.Minute || skew > Resolution || skew < -Resolution {
		return p
	}
	if sample.Epoch == prev.sample.Epoch && sample.Value < prev.sample.Value {
		return p
	}
	value := sample.Value
	if sample.Epoch == prev.sample.Epoch {
		value -= prev.sample.Value
	}
	p.V = &value
	p.D = int(elapsed / time.Second)
	if p.D <= 0 {
		p.V = nil
		return p
	}
	switch {
	case sample.Epoch != prev.sample.Epoch:
		p.Q = wire.QualityReset
	case elapsed == Resolution && wall.Equal(end) && prev.wall.Equal(end.Add(-Resolution)):
		p.T = end.Add(-Resolution)
		p.Q = wire.QualityObserved
	default:
		p.Q = wire.QualityPartial
	}
	return p
}
