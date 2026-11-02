// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
)

var base = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)

func val(n uint64) *uint64 { return &n }
func sample(n uint64) wire.CounterSample {
	return wire.CounterSample{Metric: wire.ProtoPackets, Dims: map[string]string{"protocol": "modbus"}, Epoch: "a", Value: n}
}

func TestTelemetryDeltaRules(t *testing.T) {
	for _, tc := range []struct {
		name          string
		elapsed, wall time.Duration
		epoch         string
		value         uint64
		q             wire.Quality
		v             *uint64
		d             int
		accept        bool
	}{
		{"observed offset", 10 * time.Second, 10 * time.Second, "a", 15, wire.QualityObserved, val(5), 10, true},
		{"observed positive jitter", 10400 * time.Millisecond, 10400 * time.Millisecond, "a", 15, wire.QualityObserved, val(5), 10, true},
		{"observed early jitter", 8500 * time.Millisecond, 8500 * time.Millisecond, "a", 15, wire.QualityObserved, val(5), 10, true},
		{"observed tolerance inclusive", 12 * time.Second, 12 * time.Second, "a", 15, wire.QualityObserved, val(5), 10, true},
		{"late partial rounds down", 12300 * time.Millisecond, 12300 * time.Millisecond, "a", 15, wire.QualityPartial, val(5), 12, true},
		{"late partial rounds up", 12500 * time.Millisecond, 12500 * time.Millisecond, "a", 15, wire.QualityPartial, val(5), 13, true},
		{"monotonic outside tolerance", 12500 * time.Millisecond, 10 * time.Second, "a", 15, wire.QualityPartial, val(5), 13, true},
		{"reset", 10 * time.Second, 10 * time.Second, "b", 3, wire.QualityReset, val(3), 10, true},
		{"decrease", 10 * time.Second, 10 * time.Second, "a", 9, wire.QualityGap, nil, 0, true},
		{"missed tick", 20600 * time.Millisecond, 20600 * time.Millisecond, "a", 40, wire.QualityPartial, val(30), 21, true},
		{"spanning reset", 20600 * time.Millisecond, 20600 * time.Millisecond, "b", 3, wire.QualityReset, val(3), 21, true},
		{"fifteen minutes", 15 * time.Minute, 15 * time.Minute, "a", 40, wire.QualityPartial, val(30), 900, true},
		{"long gap", 15*time.Minute + time.Second, 15*time.Minute + time.Second, "a", 40, wire.QualityGap, nil, 0, true},
		{"wall step", 10 * time.Second, 21 * time.Second, "a", 15, wire.QualityGap, nil, 0, true},
		{"backward wall step", 10 * time.Second, -11 * time.Second, "a", 15, wire.QualityGap, nil, 0, true},
		{"zero elapsed", 0, 10 * time.Second, "a", 15, wire.QualityGap, nil, 0, true},
		{"negative elapsed", -time.Second, 10 * time.Second, "a", 15, wire.QualityGap, nil, 0, true},
		{"same slot", 5 * time.Second, 5 * time.Second, "a", 15, wire.QualityGap, nil, 0, false},
		{"subsecond across slots", 900 * time.Millisecond, 10 * time.Second, "a", 15, wire.QualityGap, nil, 0, false},
		{"minimum duration", time.Second, 10 * time.Second, "a", 15, wire.QualityPartial, val(5), 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sample(tc.value)
			s.Epoch = tc.epoch
			start := base.Add(sampleOffset)
			p, accept := delta(previous{sample: sample(10), wall: start}, s, start.Add(tc.wall), tc.elapsed)
			slot, _ := sampleSlot(start.Add(tc.wall))
			if accept != tc.accept || p.Q != tc.q || p.D != tc.d || (p.V == nil) != (tc.v == nil) || p.V != nil && *p.V != *tc.v || !p.T.Equal(slot.Add(-Resolution)) {
				t.Fatalf("got %+v accepted=%v want %s v=%v d=%d accepted=%v", p, accept, tc.q, tc.v, tc.d, tc.accept)
			}
		})
	}
}

func TestTelemetrySampleSlots(t *testing.T) {
	for _, tc := range []struct {
		offset time.Duration
		slot   int
		onTime bool
	}{
		{-2*time.Second - time.Nanosecond, -1, false},
		{-2 * time.Second, 0, true},
		{0, 0, true},
		{2 * time.Second, 0, true},
		{2*time.Second + time.Nanosecond, 0, false},
		{8*time.Second - time.Nanosecond, 0, false},
		{8 * time.Second, 1, true},
		{10 * time.Second, 1, true},
	} {
		slot, onTime := sampleSlot(base.Add(sampleOffset + tc.offset))
		if !slot.Equal(base.Add(time.Duration(tc.slot)*Resolution)) || onTime != tc.onTime {
			t.Fatalf("offset %v: %v %v", tc.offset, slot, onTime)
		}
	}
	late := base.Add(sampleOffset + 3*time.Second)
	p, accept := delta(previous{sample: sample(10), wall: late}, sample(15), late.Add(Resolution), Resolution)
	if !accept || p.Q != wire.QualityPartial {
		t.Fatal("a late baseline cannot yield observed coverage", p, accept)
	}
}

func TestTelemetryOnTimeDayHasCompleteRollups(t *testing.T) {
	// Exercise a full dashboard window without 8,641 disk transactions. Storage
	// roll-up and dashboard aggregation have independent integration tests.
	prev := previous{sample: sample(10), wall: base.Add(sampleOffset)}
	points := make([]wire.Point, 0, 1440)
	minute := make([]wire.Point, 0, 6)
	for n := 1; n <= 8640; n++ {
		jitter := time.Duration(n%5-2) * 300 * time.Millisecond
		mono := time.Duration(n)*Resolution + jitter
		wall := base.Add(sampleOffset + mono)
		current := sample(uint64(10 + n))
		p, accept := delta(prev, current, wall, mono)
		if !accept || p.Q != wire.QualityObserved || p.D != 10 || *p.V != 1 {
			t.Fatalf("tick %d: %+v accepted=%v", n, p, accept)
		}
		prev = previous{sample: current, wall: wall, mono: mono}
		minute = append(minute, p)
		if len(minute) == 6 {
			rolled, err := Combine(minute, true, minute[0].T)
			if err != nil || rolled.Q != wire.QualityObserved || rolled.D != 60 {
				t.Fatal(rolled, err)
			}
			points = append(points, rolled)
			minute = minute[:0]
		}
	}
	total, complete, err := Total(wire.SeriesResponse{Series: []wire.Series{{Points: points}}})
	if err != nil || total != 8640 || !complete || len(points) != 1440 {
		t.Fatal(total, complete, len(points), err)
	}
}

func TestCombineQualitiesAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		name      string
		qualities []wire.Quality
		temporal  bool
		want      wire.Quality
	}{
		{"observed", []wire.Quality{wire.QualityObserved, wire.QualityObserved}, true, wire.QualityObserved},
		{"partial", []wire.Quality{wire.QualityObserved, wire.QualityGap}, true, wire.QualityPartial},
		{"roll reset beats gap", []wire.Quality{wire.QualityReset, wire.QualityGap}, true, wire.QualityReset},
		{"group gap beats reset", []wire.Quality{wire.QualityReset, wire.QualityGap}, false, wire.QualityPartial},
		{"group partial beats reset", []wire.Quality{wire.QualityReset, wire.QualityPartial}, false, wire.QualityPartial},
		{"group reset", []wire.Quality{wire.QualityReset, wire.QualityObserved}, false, wire.QualityReset},
		{"none", []wire.Quality{wire.QualityGap, wire.QualityGap}, true, wire.QualityGap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			points := []wire.Point{}
			for _, q := range tc.qualities {
				p := wire.Point{Q: q}
				if q != wire.QualityGap {
					p.V = val(3)
					p.D = 10
				}
				points = append(points, p)
			}
			got, err := Combine(points, tc.temporal, base)
			if err != nil || got.Q != tc.want {
				t.Fatalf("%+v %v", got, err)
			}
		})
	}
	p, err := Combine([]wire.Point{{V: val(2), D: 30, Q: wire.QualityObserved}, {V: val(3), D: 10, Q: wire.QualityObserved}}, false, base)
	if err != nil || *p.V != 5 || p.D != 0 || p.Q != wire.QualityPartial {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err = Combine([]wire.Point{{V: val(math.MaxUint64)}, {V: val(1)}}, false, base); err != ErrOverflow {
		t.Fatal(err)
	}
}

func TestNextTickWallAligned(t *testing.T) {
	for _, offset := range []time.Duration{0, 100 * time.Millisecond, 200 * time.Millisecond, 9 * time.Second} {
		now := base.Add(offset)
		next := nextTick(now)
		if !next.After(now) || next.Nanosecond() != int(sampleOffset) || next.Second()%10 != 0 {
			t.Fatal(now, next)
		}
	}
}

func TestGroupDurationAgreement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		points []wire.Point
		d      int
		q      wire.Quality
	}{
		{"equal", []wire.Point{{V: val(2), D: 10, Q: wire.QualityObserved}, {V: val(3), D: 10, Q: wire.QualityObserved}}, 10, wire.QualityObserved},
		{"unequal", []wire.Point{{V: val(2), D: 10, Q: wire.QualityObserved}, {V: val(3), D: 30, Q: wire.QualityObserved}}, 0, wire.QualityPartial},
		{"gap ignored for duration", []wire.Point{{V: val(2), D: 10, Q: wire.QualityObserved}, {Q: wire.QualityGap}}, 10, wire.QualityPartial},
		{"reset with unequal", []wire.Point{{V: val(2), D: 10, Q: wire.QualityReset}, {V: val(3), D: 30, Q: wire.QualityObserved}}, 0, wire.QualityPartial},
		{"unknown duration", []wire.Point{{V: val(2), D: 0, Q: wire.QualityPartial}, {V: val(3), D: 10, Q: wire.QualityObserved}}, 0, wire.QualityPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Combine(tc.points, false, base)
			if err != nil || p.D != tc.d || p.Q != tc.q {
				t.Fatalf("%+v %v", p, err)
			}
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if tc.d == 0 && bytes.Contains(b, []byte(`"d":`)) {
				t.Fatal(string(b))
			}
		})
	}
}

func TestDimensionIdentityNormalizesEmptyMaps(t *testing.T) {
	a, b := sample(0), sample(0)
	a.Dims = nil
	b.Dims = map[string]string{}
	if identity(a) != identity(b) {
		t.Fatal("empty dimensions created a different series")
	}
}
