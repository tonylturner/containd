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

func TestDeltaRules(t *testing.T) {
	for _, tc := range []struct {
		name          string
		elapsed, wall time.Duration
		epoch         string
		value         uint64
		q             wire.Quality
		v             *uint64
		d             int
	}{
		{"observed", 10 * time.Second, 10 * time.Second, "a", 15, wire.QualityObserved, val(5), 10},
		{"partial", 5 * time.Second, 5 * time.Second, "a", 15, wire.QualityPartial, val(5), 5},
		{"reset", 10 * time.Second, 10 * time.Second, "b", 3, wire.QualityReset, val(3), 10},
		{"decrease", 10 * time.Second, 10 * time.Second, "a", 9, wire.QualityGap, nil, 0},
		{"spanning", 30 * time.Second, 30 * time.Second, "a", 40, wire.QualityPartial, val(30), 30},
		{"fifteen minutes", 15 * time.Minute, 15 * time.Minute, "a", 40, wire.QualityPartial, val(30), 900},
		{"long gap", 15*time.Minute + time.Second, 15*time.Minute + time.Second, "a", 40, wire.QualityGap, nil, 0},
		{"wall step", 10 * time.Second, 21 * time.Second, "a", 15, wire.QualityGap, nil, 0},
		{"backward wall step", 10 * time.Second, -time.Second, "a", 15, wire.QualityGap, nil, 0},
		{"zero elapsed", 0, 0, "a", 15, wire.QualityGap, nil, 0},
		{"negative elapsed", -time.Second, -time.Second, "a", 15, wire.QualityGap, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sample(tc.value)
			s.Epoch = tc.epoch
			p := delta(previous{sample: sample(10), wall: base}, s, base.Add(tc.wall), tc.elapsed)
			if p.Q != tc.q || p.D != tc.d || (p.V == nil) != (tc.v == nil) || p.V != nil && *p.V != *tc.v {
				t.Fatalf("got %+v want %s v=%v d=%d", p, tc.q, tc.v, tc.d)
			}
		})
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
