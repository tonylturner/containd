// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"math"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
)

func TestDemoSecurityRestoresCoarseHistory(t *testing.T) {
	for name, value := range map[string]uint64{"zero": 0, "multibyte": 128, "uint64_max": math.MaxUint64} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := newStore(t)
			err := s.write(ctx, base.Add(Resolution), []row{{
				sample: wire.CounterSample{Metric: wire.EventsClass, Dims: map[string]string{"source": "engine", "class": "av_block"}},
				point:  wire.Point{T: base, V: &value, D: 10, Q: wire.QualityPartial},
			}})
			if err != nil {
				t.Fatal(err)
			}
			// Only coarse retained history is available on this old store.
			if _, err := s.db.Exec("DELETE FROM coverage WHERE metric=?; DELETE FROM buckets WHERE resolution!=900", demoSecurityCoverage); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(s.path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			ready, active, err := reopened.DemoState(ctx)
			if err != nil || ready || active != (value > 0) {
				t.Fatal(ready, active, err)
			}
		})
	}
}

func TestDemoStateActivity(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		sample wire.CounterSample
		stops  bool
	}{
		{"interface_rx", wire.CounterSample{Metric: wire.IfaceRxBytes}, false},
		{"interface_tx", wire.CounterSample{Metric: wire.IfaceTxBytes}, false},
		{"conduit_bytes", wire.CounterSample{Metric: wire.ConduitBytes}, true},
		{"conduit_packets", wire.CounterSample{Metric: wire.ConduitPackets}, false},
		{"engine_events", wire.CounterSample{Metric: wire.EventsTotal, Dims: map[string]string{"source": "engine"}}, false},
		{"engine_health", wire.CounterSample{Metric: wire.EventsClass, Dims: map[string]string{"source": "engine", "class": "health"}}, false},
		{"engine_startup", wire.CounterSample{Metric: wire.EventsClass, Dims: map[string]string{"source": "engine", "class": "startup"}}, false},
		{"modbus_write", wire.CounterSample{Metric: wire.EventsClass, Dims: map[string]string{"source": "engine", "class": "modbus_write"}}, false},
		{"service_alert", wire.CounterSample{Metric: wire.EventsClass, Dims: map[string]string{"source": "services", "class": "ids_alert"}}, false},
		{"unsourced_alert", wire.CounterSample{Metric: wire.EventsClass, Dims: map[string]string{"class": "ids_alert"}}, false},
		{"ids_alert", wire.CounterSample{Metric: wire.EventsClass, Dims: map[string]string{"source": "engine", "class": "ids_alert"}}, true},
		{"av_detection", wire.CounterSample{Metric: wire.EventsClass, Dims: map[string]string{"source": "engine", "class": "av_detection"}}, true},
		{"av_block", wire.CounterSample{Metric: wire.EventsClass, Dims: map[string]string{"source": "engine", "class": "av_block"}}, true},
		{"demo_conduit", wire.CounterSample{Metric: wire.ConduitBytes, Origin: wire.OriginDemo}, false},
		{"demo_alert", wire.CounterSample{Metric: wire.EventsClass, Origin: wire.OriginDemo, Dims: map[string]string{"source": "engine", "class": "ids_alert"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "telemetry.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			// Omitted origin is real. A nonzero first reading is only a baseline.
			tc.sample.Epoch, tc.sample.Value = "epoch", 100
			reader := &fakeReader{samples: []wire.CounterSample{tc.sample, {Metric: wire.ServiceEvents, Epoch: "mgmt"}}}
			sampler := NewSampler(s, reader)
			check := func(ready, active bool) {
				t.Helper()
				gotReady, gotActive, err := s.DemoState(ctx)
				if err != nil || gotReady != ready || gotActive != active {
					t.Fatal(gotReady, gotActive, err)
				}
			}
			tick := func(sec int) {
				t.Helper()
				if err := sampler.Tick(ctx, base.Add(time.Duration(sec)*time.Second), time.Duration(sec)*time.Second); err != nil {
					t.Fatal(err)
				}
			}
			tick(0)
			check(false, false)
			tick(10)
			check(true, false)
			reader.samples[0].Value++
			tick(20)
			check(true, tc.stops)
			resp := query(t, s, base.Add(20*time.Second), Query{Metric: tc.sample.Metric, Range: wire.Range1h, Origin: wire.OriginReal})
			if resp.RealActive != (tc.sample.Origin != wire.OriginDemo) {
				t.Fatal("chart activity changed", resp.RealActive)
			}
			reader.samples = nil
			tick(30)
			check(true, tc.stops)
			// Model an upgrade: only the old metric-wide coverage is present.
			// Scoped security activity must be recovered from retained history.
			if _, err := s.db.Exec("DELETE FROM coverage WHERE metric=?", demoSecurityCoverage); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			check(false, tc.stops)
			// Retention may delete every bucket and series; both independent
			// activity authorities must survive another restart.
			if err := s.maintain(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("DELETE FROM buckets; DELETE FROM series"); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			check(false, tc.stops)
			resp = query(t, s, base.Add(40*time.Second), Query{Metric: tc.sample.Metric, Range: wire.Range1h, Origin: wire.OriginReal})
			if resp.RealActive != (tc.sample.Origin != wire.OriginDemo) {
				t.Fatal("lost persistent chart activity", resp.RealActive)
			}
		})
	}
}

func TestDemoReadinessNeedsObservedRealInterval(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	reader := &fakeReader{samples: []wire.CounterSample{{Metric: wire.IfaceRxBytes, Origin: wire.OriginDemo, Epoch: "demo"}}}
	sampler := NewSampler(s, reader)
	callbacks := 0
	sampler.AfterTick = func(ctx context.Context) {
		callbacks++
		// Callback can query the store; neither sampler nor store locks are held.
		if _, _, err := s.DemoState(ctx); err != nil {
			t.Error(err)
		}
	}
	for i := range 2 {
		if err := sampler.Tick(ctx, base.Add(time.Duration(i)*Resolution), time.Duration(i)*Resolution); err != nil {
			t.Fatal(err)
		}
	}
	if ready, active, err := s.DemoState(ctx); ready || active || err != nil {
		t.Fatal(ready, active, err)
	}
	// Unconnected appliances still have observed management service intervals.
	reader.samples = []wire.CounterSample{{Metric: wire.ServiceEvents, Epoch: "mgmt"}}
	for i := 2; i < 4; i++ {
		if err := sampler.Tick(ctx, base.Add(time.Duration(i)*Resolution), time.Duration(i)*Resolution); err != nil {
			t.Fatal(err)
		}
	}
	if ready, active, err := s.DemoState(ctx); !ready || active || err != nil {
		t.Fatal(ready, active, err)
	}
	if callbacks != 4 {
		t.Fatal(callbacks)
	}
}
