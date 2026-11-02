// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"testing"

	"github.com/tonylturner/containd/pkg/common/evidence"
	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestServiceTelemetrySignedCorrectionAndNoDemo(t *testing.T) {
	m := NewManager(ManagerOptions{BaseDir: t.TempDir()})
	reader := m.CounterReader("mgmt")
	m.IncrementServiceMetric("dns", 10)
	m.IncrementServiceMetric("dns", -2)
	m.IncrementServiceMetric("dns", 5)
	m.telemetry.Append(dpevents.Event{Origin: wire.OriginDemo, Kind: "demo"})
	snapshot, err := reader.TelemetryCounters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	signed := false
	demo := false
	for _, u := range snapshot.Unavailable {
		signed = signed || u.Metric == wire.ServiceEvents && u.Dims["service"] == "dns"
	}
	for _, s := range snapshot.Samples {
		if s.Metric == wire.ServiceEvents && s.Dims["service"] == "dns" {
			t.Fatal("signed correction must not look monotonic")
		}
		if s.Origin == wire.OriginDemo {
			demo = true
		}
	}
	if !signed || demo {
		t.Fatal(snapshot)
	}
	snapshot, err = reader.TelemetryCounters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range snapshot.Samples {
		if s.Metric == wire.ServiceEvents && s.Dims["service"] == "dns" {
			found = s.Value == 13 && s.Epoch == "mgmt"
		}
	}
	if !found {
		t.Fatal(snapshot)
	}
}

func TestSyslogSkipsDemoAndAdvancesCursor(t *testing.T) {
	store := dpevents.NewStore(32)
	before := store.ReadFeed(dpevents.FeedRequest{TailOnly: true})
	store.Append(dpevents.Event{Origin: wire.OriginDemo, Kind: "demo"})
	page := store.ReadFeed(dpevents.FeedRequest{Epoch: before.Epoch, After: before.Tail})
	m := NewSyslogManager()
	read := func(context.Context, dpevents.FeedRequest) (dpevents.FeedPage, error) { return page, nil }
	progress, sent, failed := m.forwardEvents(context.Background(), syslogTarget{network: "invalid", addr: "invalid"}, evidence.SourceEngine, read, eventProgress{epoch: before.Epoch, offset: before.Tail}, "json", 100)
	if sent != 0 || failed != 0 || progress.offset != page.Tail || progress.lost != 0 {
		t.Fatal(progress, sent, failed)
	}
}
