// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

type fakeReader struct {
	samples     []wire.CounterSample
	err         error
	unavailable []wire.SourceUnavailable
	invalid     []wire.CounterSample
}

func (r *fakeReader) TelemetryCounters(context.Context) (wire.CounterSnapshot, error) {
	return wire.CounterSnapshot{Samples: r.samples, Unavailable: r.unavailable}, r.err
}
func (r *fakeReader) TelemetryBaselines() []wire.CounterSample { return r.invalid }

func query(t *testing.T, s *Store, now time.Time, q Query) wire.SeriesResponse {
	t.Helper()
	out, err := s.Query(context.Background(), q, now)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var protoQuery = Query{Metric: wire.ProtoPackets, Range: wire.Range1h, Origin: wire.OriginReal}

func TestSamplerAbsenceRestartFailureAndDensePoints(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	engine := &fakeReader{samples: []wire.CounterSample{sample(10)}}
	localSample := wire.CounterSample{Metric: wire.ServiceEvents, Dims: map[string]string{"service": "dns"}, Value: 10, Epoch: "mgmt"}
	local := &fakeReader{samples: []wire.CounterSample{localSample}}
	collector := NewSampler(s, engine, local)
	tick := func(seconds int) {
		t.Helper()
		if err := collector.Tick(ctx, base.Add(time.Duration(seconds)*time.Second), time.Duration(seconds)*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	tick(0)
	engine.samples[0].Value = 15
	local.samples[0].Value = 12
	tick(10)
	out := query(t, s, base.Add(10*time.Second), protoQuery)
	if len(out.Series) != 1 || len(out.Series[0].Points) != 360 || out.Series[0].Points[359].Q != wire.QualityObserved || *out.Series[0].Points[359].V != 5 || !out.RealActive || !out.RealCovered {
		t.Fatalf("bad dense response: %+v", out)
	}
	// The current bucket is not returned, even if it has a stored point.
	if out.Series[0].Points[359].T != base {
		t.Fatal("open bucket included")
	}
	engine.err = errors.New("engine offline")
	local.samples[0].Value = 16
	tick(20)
	out = query(t, s, base.Add(20*time.Second), protoQuery)
	if out.Series[0].Points[359].V != nil {
		t.Fatal("outage became zero")
	}
	localOut := query(t, s, base.Add(20*time.Second), Query{Metric: wire.ServiceEvents, Range: wire.Range1h, Origin: wire.OriginReal})
	if p := localOut.Series[0].Points[359]; p.V == nil || *p.V != 4 {
		t.Fatal("engine suppressed local sample", p)
	}
	engine.err = nil
	engine.samples[0].Value = 30
	tick(30)
	out = query(t, s, base.Add(40*time.Second), protoQuery)
	p := out.Series[0].Points[359]
	if p.Q != wire.QualityPartial || p.D != 20 || *p.V != 15 {
		t.Fatal(p)
	}
	collector = NewSampler(s, engine, local)
	tick(40)
	out = query(t, s, base.Add(50*time.Second), protoQuery)
	if out.Series[0].Points[359].V != nil {
		t.Fatal("collector restart must baseline")
	}
	// Reopening preserves coverage, but never in-memory baselines.
	path := s.path
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	out = query(t, reopened, base.Add(40*time.Second), protoQuery)
	if !out.RealActive || !out.RealCovered {
		t.Fatal("lost persisted coverage")
	}
}

func TestStoreRollupRetentionCapAndExpiry(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	rows := []row{}
	for n := range 6 {
		rows = append(rows, row{sample: sample(0), point: wire.Point{T: base.Add(time.Duration(n) * Resolution), V: val(2), D: 10, Q: wire.QualityObserved}})
	}
	if err := s.write(ctx, base.Add(time.Minute), rows); err != nil {
		t.Fatal(err)
	}
	out := query(t, s, base.Add(time.Minute), Query{Metric: wire.ProtoPackets, Range: wire.Range24h, Origin: wire.OriginReal})
	p := out.Series[0].Points[1439]
	if p.Q != wire.QualityObserved || p.D != 60 || *p.V != 12 {
		t.Fatal(p)
	}
	rows = nil
	for n := range SeriesLimit + 1 {
		sp := sample(0)
		sp.Dims = map[string]string{"protocol": fmt.Sprint(n)}
		rows = append(rows, row{sample: sp})
	}
	if err := s.write(ctx, base.Add(time.Minute), rows); err != nil {
		t.Fatal(err)
	}
	if s.State().DroppedSeries != 2 {
		t.Fatal(s.State())
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM series").Scan(&count); err != nil || count != SeriesLimit {
		t.Fatal(count, err)
	}
	if err := s.write(ctx, base.Add(31*24*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT count(*) FROM series").Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
}

func TestStoreWriteFailureStallsWithoutBuckets(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	reader := &fakeReader{samples: []wire.CounterSample{sample(3)}}
	sampler := NewSampler(s, reader)
	if err := sampler.Tick(ctx, base, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	reader.samples[0].Value = 4
	if err := sampler.Tick(ctx, base.Add(Resolution), Resolution); err == nil {
		t.Fatal("write succeeded")
	}
	if state := s.State(); state.State != "stalled" || state.Error == "" {
		t.Fatal(state)
	}
	if _, err := s.db.Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	out := query(t, s, base.Add(Resolution), protoQuery)
	if out.Series[0].Points[359].V != nil {
		t.Fatal("failed write fabricated a bucket")
	}
}

func TestGroupingZoneExcludesParentsAndOverflows(t *testing.T) {
	s := newStore(t)
	rows := []row{}
	for _, role := range []string{"leaf", "parent"} {
		for _, iface := range []string{"eth0", "eth1"} {
			sp := wire.CounterSample{Metric: wire.IfaceRxBytes, Dims: map[string]string{"role": role, "interface": iface, "zone": "lan"}}
			rows = append(rows, row{sample: sp, point: wire.Point{T: base, V: val(3), D: 10, Q: wire.QualityObserved}})
		}
	}
	if err := s.write(context.Background(), base.Add(Resolution), rows); err != nil {
		t.Fatal(err)
	}
	q := Query{Metric: wire.IfaceRxBytes, Range: wire.Range1h, Origin: wire.OriginReal, Group: "zone"}
	out := query(t, s, base.Add(Resolution), q)
	if len(out.Series) != 1 || *out.Series[0].Points[359].V != 6 {
		t.Fatal(out)
	}
	rows[0].point.V = val(^uint64(0) - 3)
	if err := s.write(context.Background(), base.Add(Resolution), rows[:1]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Query(context.Background(), q, base.Add(Resolution)); !errors.Is(err, ErrOverflow) {
		t.Fatal(err)
	}
}

func TestParseQueryRejectsUnknownAndRepeated(t *testing.T) {
	for _, raw := range []string{"metric=bad&range=1h&origin=real", "metric=proto.packets&range=2h&origin=real", "metric=proto.packets&range=1h&origin=bad", "metric=proto.packets&range=1h&origin=real&zone=lan", "metric=proto.packets&range=1h&origin=real&group=zone", "metric=proto.packets&range=1h&origin=real&protocol=a&protocol=b"} {
		v, err := url.ParseQuery(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ParseQuery(v); err == nil {
			t.Fatal(raw)
		}
	}
}

func TestBudgetEvictionReclaimsAndMovesFloor(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	// A small test budget exercises the same physical reclamation path.
	for i := range 3000 {
		p := wire.Point{T: base.Add(time.Duration(i) * 15 * time.Minute), V: val(1), D: 900, Q: wire.QualityObserved}
		tx, err := s.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err = put(ctx, tx, 1, 900, p); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	before, err := s.diskBytes()
	if err != nil {
		t.Fatal(err)
	}
	s.reclaim = 64 << 10
	s.budget = BudgetBytes
	if err = s.maintain(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := s.diskBytes()
	if err != nil {
		t.Fatal(err)
	}
	if after >= before || after >= s.reclaim {
		t.Fatalf("reclamation %d -> %d", before, after)
	}
	var floor int64
	if err = s.db.QueryRow("SELECT t FROM floors WHERE resolution=900").Scan(&floor); err != nil || floor <= base.Unix() {
		t.Fatal(floor, err)
	}
	var mode int
	if err = s.db.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil || mode != 2 {
		t.Fatal(mode, err)
	}
}

func TestSamplerLongGapAndDimensionChangesBaseline(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	reader := &fakeReader{samples: []wire.CounterSample{sample(10)}}
	sampler := NewSampler(s, reader)
	tick := func(at time.Duration) {
		t.Helper()
		if err := sampler.Tick(ctx, base.Add(at), at); err != nil {
			t.Fatal(err)
		}
	}
	tick(0)
	reader.samples[0].Value = 30
	tick(16 * time.Minute)
	out := query(t, s, base.Add(16*time.Minute), protoQuery)
	if out.Series[0].Points[359].V != nil {
		t.Fatal("long interval must baseline")
	}
	reader.samples[0].Value = 35
	tick(16*time.Minute + Resolution)
	out = query(t, s, base.Add(16*time.Minute+Resolution), protoQuery)
	if p := out.Series[0].Points[359]; p.V == nil || *p.V != 5 || p.Q != wire.QualityObserved {
		t.Fatal(p)
	}
	reader.samples[0].Dims["protocol"] = "dnp3"
	reader.samples[0].Value = 100
	tick(16*time.Minute + 2*Resolution)
	out = query(t, s, base.Add(16*time.Minute+2*Resolution), protoQuery)
	for _, series := range out.Series {
		if series.Points[359].V != nil {
			t.Fatal("new dims baseline, absent old dims gap", series)
		}
	}
}

func TestSamplerStopJoinsWriter(t *testing.T) {
	s := newStore(t)
	sampler := NewSampler(s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sampler.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sampler did not stop")
	}
}

func TestPhysicalReservationBoundsEntireDatabaseWAL(t *testing.T) {
	s := newStore(t)
	var pages int64
	if err := s.db.QueryRow("PRAGMA max_page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	// A commit can dirty every main-file page, but never emit it twice because
	// cache spilling is disabled. WAL adds a 24-byte frame header per page.
	if worst := pages*4096 + pages*(4096+24) + 32; worst > BudgetBytes {
		t.Fatal(worst)
	}
	var spill int
	if err := s.db.QueryRow("PRAGMA cache_spill").Scan(&spill); err != nil || spill != 0 {
		t.Fatal(spill, err)
	}
}

func TestOpenBucketExcludedAndOffsetPartial(t *testing.T) {
	s := newStore(t)
	reader := &fakeReader{samples: []wire.CounterSample{sample(10)}}
	sampler := NewSampler(s, reader)
	ctx := context.Background()
	if err := sampler.Tick(ctx, base.Add(sampleOffset), 0); err != nil {
		t.Fatal(err)
	}
	reader.samples[0].Value = 15
	if err := sampler.Tick(ctx, base.Add(Resolution+sampleOffset), Resolution); err != nil {
		t.Fatal(err)
	}
	out := query(t, s, base.Add(Resolution+sampleOffset), protoQuery)
	for _, p := range out.Series[0].Points {
		if p.V != nil {
			t.Fatal("open bucket leaked", p)
		}
	}
	out = query(t, s, base.Add(2*Resolution+sampleOffset), protoQuery)
	p := out.Series[0].Points[359]
	if p.T != base.Add(Resolution) || p.V == nil || *p.V != 5 || p.Q != wire.QualityPartial || p.D != 10 {
		t.Fatal(p)
	}
}

func TestSpanningThenAlignedPreservesBothDeltas(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	reader := &fakeReader{samples: []wire.CounterSample{sample(10)}}
	sampler := NewSampler(s, reader)
	for _, tick := range []struct {
		seconds int
		value   uint64
	}{{0, 10}, {30, 40}, {40, 45}} {
		reader.samples[0].Value = tick.value
		if err := sampler.Tick(ctx, base.Add(time.Duration(tick.seconds)*time.Second), time.Duration(tick.seconds)*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	out := query(t, s, base.Add(40*time.Second), protoQuery)
	p := out.Series[0].Points[359]
	if p.V == nil || *p.V != 35 || p.D != 40 || p.Q != wire.QualityPartial || out.RealCovered {
		t.Fatal(p, out.RealCovered)
	}
}

func TestSignedServiceCorrectionEstablishesNewBaseline(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	counter := wire.CounterSample{Metric: wire.ServiceEvents, Dims: map[string]string{"service": "dns"}, Value: 10, Epoch: "mgmt"}
	reader := &fakeReader{samples: []wire.CounterSample{counter}}
	sampler := NewSampler(s, reader)
	tick := func(n int) {
		t.Helper()
		if err := sampler.Tick(ctx, base.Add(time.Duration(n)*Resolution), time.Duration(n)*Resolution); err != nil {
			t.Fatal(err)
		}
	}
	tick(0)
	reader.samples = nil
	reader.invalid = []wire.CounterSample{counter}
	tick(1)
	reader.invalid = nil
	counter.Value = 15
	reader.samples = []wire.CounterSample{counter}
	tick(2)
	out := query(t, s, base.Add(3*Resolution), Query{Metric: wire.ServiceEvents, Range: wire.Range1h, Origin: wire.OriginReal})
	for _, p := range out.Series[0].Points {
		if p.V != nil {
			t.Fatal("signed correction must not become a reset or spanning delta", p)
		}
	}
	reader.samples[0].Value = 18
	tick(3)
	out = query(t, s, base.Add(3*Resolution), Query{Metric: wire.ServiceEvents, Range: wire.Range1h, Origin: wire.OriginReal})
	if p := out.Series[0].Points[359]; p.V == nil || *p.V != 3 || p.Q != wire.QualityObserved {
		t.Fatal(p)
	}
}

func TestStoreSchemaMismatchRejected(t *testing.T) {
	s := newStore(t)
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := checkSchema(version+1, 1); err == nil {
		t.Fatal("mismatched telemetry schema accepted")
	}
	if err := checkSchema(0, 1); err == nil {
		t.Fatal("unversioned existing telemetry tables accepted")
	}
}

func TestObservedZeroIsCoveredNotActive(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	reader := &fakeReader{samples: []wire.CounterSample{sample(0)}}
	sampler := NewSampler(s, reader)
	if err := sampler.Tick(ctx, base, 0); err != nil {
		t.Fatal(err)
	}
	if err := sampler.Tick(ctx, base.Add(Resolution), Resolution); err != nil {
		t.Fatal(err)
	}
	out := query(t, s, base.Add(Resolution), protoQuery)
	p := out.Series[0].Points[359]
	if p.V == nil || *p.V != 0 || p.Q != wire.QualityObserved || !out.RealCovered || out.RealActive {
		t.Fatal(p, out.RealCovered, out.RealActive)
	}
}

func TestSamplerAdmissionSurvivesRestartAndChangedReadOrder(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	rows := []row{}
	for n := range SeriesLimit {
		sp := sample(0)
		sp.Dims = map[string]string{"protocol": fmt.Sprint(n)}
		rows = append(rows, row{sample: sp})
	}
	if err := s.write(ctx, base, rows); err != nil {
		t.Fatal(err)
	}
	refused := sample(0)
	refused.Dims = map[string]string{"protocol": "refused"}
	reader := &fakeReader{samples: []wire.CounterSample{refused}}
	for _, row := range rows {
		reader.samples = append(reader.samples, row.sample)
	}
	sampler := NewSampler(s, reader)
	if err := sampler.Tick(ctx, base, 0); err != nil {
		t.Fatal(err)
	}
	for i := range reader.samples {
		reader.samples[i].Value = 1
	}
	if err := sampler.Tick(ctx, base.Add(Resolution), Resolution); err != nil {
		t.Fatal(err)
	}
	if len(sampler.previous) != SeriesLimit {
		t.Fatal(len(sampler.previous))
	}
	if _, ok := sampler.previous[identity(refused)]; ok {
		t.Fatal("refused series occupied a baseline slot")
	}
	out := query(t, s, base.Add(Resolution), protoQuery)
	if len(out.Series) != SeriesLimit {
		t.Fatal(len(out.Series))
	}
	for _, series := range out.Series {
		if p := series.Points[359]; p.V == nil || *p.V != 1 || p.Q != wire.QualityObserved {
			t.Fatal(series.Dims, p)
		}
	}
}
