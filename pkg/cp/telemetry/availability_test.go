// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
)

func TestSamplerCurrentUnavailableReplacedAndIsolated(t *testing.T) {
	s := newStore(t)
	engine := &fakeReader{unavailable: []wire.SourceUnavailable{
		{Source: "conduit", Reason: "enforcement disabled"},
		{Source: "iface", Metric: wire.IfaceRxBytes, Dims: map[string]string{"interface": "eth0"}, Reason: "missing device"},
	}}
	local := &fakeReader{unavailable: []wire.SourceUnavailable{{Source: "service", Reason: "meter unavailable"}}}
	sampler := NewSampler(s, engine, local)
	tick := func(n int) {
		t.Helper()
		if err := sampler.Tick(context.Background(), base.Add(Resolution*time.Duration(n)), Resolution*time.Duration(n)); err != nil {
			t.Fatal(err)
		}
	}
	tick(0)
	want := append(append([]wire.SourceUnavailable(nil), engine.unavailable...), local.unavailable...)
	if got := s.State().Unavailable; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// Neither producers nor returned responses may mutate collector state.
	engine.unavailable[1].Dims["interface"] = "changed"
	state := s.State()
	state.Unavailable[0].Reason = "changed"
	state.Unavailable[1].Dims["interface"] = "changed"
	out := query(t, s, base, Query{Metric: wire.IfaceRxBytes, Range: wire.Range1h, Origin: wire.OriginReal})
	out.Collector.Unavailable[0].Dims["interface"] = "changed"
	if got := s.State().Unavailable; got[0].Reason != "enforcement disabled" || got[1].Dims["interface"] != "eth0" {
		t.Fatal("availability state aliased", got)
	}

	engine.unavailable = nil
	engine.err = errors.New("engine offline")
	tick(1)
	want = []wire.SourceUnavailable{{Source: "engine", Reason: "engine offline"}, local.unavailable[0]}
	if got := s.State().Unavailable; !reflect.DeepEqual(got, want) || s.State().State != "running" {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	engine.err, local.unavailable = nil, nil
	tick(2)
	if got := s.State().Unavailable; len(got) != 0 {
		t.Fatal("recovery retained stale availability", got)
	}
}

func TestTelemetrySeriesCurrentUnavailableSelection(t *testing.T) {
	s := newStore(t)
	entries := []wire.SourceUnavailable{
		{Source: "engine", Reason: "engine offline"},
		{Source: "iface", Reason: "links unavailable"},
		{Source: "iface", Metric: wire.IfaceRxBytes, Dims: map[string]string{"interface": "eth0", "zone": "lan", "role": "leaf"}, Reason: "eth0 missing"},
		{Source: "iface", Metric: wire.IfaceTxBytes, Dims: map[string]string{"interface": "eth1", "zone": "wan", "role": "parent"}, Reason: "eth1 missing"},
		{Source: "conduit", Metric: wire.ConduitBytes, Dims: map[string]string{"from": "lan", "to": "wan"}, Reason: "pair unavailable"},
		{Source: "proto", Reason: "protocol tracker unavailable"},
		{Source: "events", Metric: wire.EventsTotal, Dims: map[string]string{"source": "engine"}, Reason: "engine events unavailable"},
		{Source: "events", Reason: "event stores unavailable"},
		{Source: "av", Reason: "scanner unavailable"},
		{Source: "service", Dims: map[string]string{"service": "dns"}, Reason: "DNS meter unavailable"},
	}
	if err := NewSampler(s, &fakeReader{unavailable: entries}).Tick(context.Background(), base, 0); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		metric  wire.Metric
		filters map[string]string
		group   string
		want    []int
	}{
		{"iface all", wire.IfaceRxBytes, nil, "", []int{0, 1, 2}},
		{"iface match", wire.IfaceRxBytes, map[string]string{"interface": "eth0"}, "", []int{0, 1, 2}},
		{"iface other", wire.IfaceRxBytes, map[string]string{"interface": "eth1"}, "", []int{0, 1}},
		{"zone leaf only", wire.IfaceTxBytes, nil, "zone", []int{0, 1}},
		{"zone match", wire.IfaceRxBytes, map[string]string{"zone": "lan"}, "zone", []int{0, 1, 2}},
		{"zone other", wire.IfaceRxBytes, map[string]string{"zone": "wan"}, "zone", []int{0, 1}},
		{"conduit match", wire.ConduitBytes, map[string]string{"from": "lan", "to": "wan"}, "", []int{0, 4}},
		{"conduit other", wire.ConduitBytes, map[string]string{"from": "wan", "to": "lan"}, "", []int{0}},
		{"conduit metric", wire.ConduitPackets, nil, "", []int{0}},
		{"proto", wire.ProtoBytes, nil, "", []int{0, 5}},
		{"events both", wire.EventsTotal, nil, "", []int{0, 6, 7}},
		{"events engine", wire.EventsTotal, map[string]string{"source": "engine"}, "", []int{0, 6, 7}},
		{"events services", wire.EventsTotal, map[string]string{"source": "services"}, "", []int{7}},
		{"events class", wire.EventsClass, nil, "", []int{0, 7}},
		{"av", wire.AVScans, nil, "", []int{0, 8}},
		{"services all", wire.ServiceEvents, nil, "", []int{9}},
		{"service match", wire.ServiceErrors, map[string]string{"service": "dns"}, "", []int{9}},
		{"service other", wire.ServiceEvents, map[string]string{"service": "ntp"}, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := Query{Metric: tc.metric, Range: wire.Range1h, Origin: wire.OriginReal, Filters: tc.filters, Group: tc.group}
			var want []wire.SourceUnavailable
			for _, i := range tc.want {
				want = append(want, entries[i])
			}
			if got := query(t, s, base, q).Collector.Unavailable; !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestSamplerCurrentUnavailableSurvivesWriteFailure(t *testing.T) {
	s := newStore(t)
	if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	reader := &fakeReader{err: errors.New("engine offline")}
	sampler := NewSampler(s, reader)
	if err := sampler.Tick(context.Background(), base, 0); err == nil {
		t.Fatal("expected write failure")
	}
	state := s.State()
	if state.State != "stalled" || len(state.Unavailable) != 1 || state.Unavailable[0].Reason != "engine offline" {
		t.Fatal(state)
	}
	reader.err = nil
	if err := sampler.Tick(context.Background(), base.Add(Resolution), Resolution); err == nil {
		t.Fatal("expected write failure")
	}
	if state := s.State(); state.State != "stalled" || len(state.Unavailable) != 0 {
		t.Fatal("current availability must not depend on persistence", state)
	}
}
