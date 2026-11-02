// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
)

func TestDemoStateSharesStickyRealActive(t *testing.T) {
	ctx := context.Background()
	for _, metric := range []wire.Metric{wire.IfaceRxBytes, wire.IfaceTxBytes, wire.ConduitBytes} {
		t.Run(string(metric), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "telemetry.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			reader := &fakeReader{samples: []wire.CounterSample{{Metric: metric, Origin: wire.OriginReal, Epoch: "epoch", Value: 100}}}
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
			check(true, true)
			resp := query(t, s, base.Add(20*time.Second), Query{Metric: metric, Range: wire.Range1h, Origin: wire.OriginReal})
			if !resp.RealActive {
				t.Fatal("demo and charts disagree")
			}
			reader.samples = nil
			tick(30)
			check(true, true)
			// Retention may delete every bucket; the chart authority survives it.
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
			check(false, true)
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
