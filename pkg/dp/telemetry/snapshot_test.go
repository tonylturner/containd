// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

func TestSnapshotQuietAndMissingSeries(t *testing.T) {
	tracker := stats.New()
	tracker.RecordPacket(netip.Addr{}, netip.Addr{}, "modbus", 0, time.Now())
	m := Bind([]config.Interface{{Name: "logical", Device: "eth0", Zone: "plant"}, {Name: "missing", Zone: "wan"}})
	c := Collector{BootID: "process", Membership: func() *Membership { return m }, Tracker: func() *stats.Tracker { return tracker }, Link: func(d string) (Link, error) {
		if d == "missing" {
			return Link{}, errors.New("device missing")
		}
		return Link{Epoch: "kernel:ns:7"}, nil
	}, Events: func() []wire.EventCounts { return []wire.EventCounts{{Origin: wire.OriginReal}} }, AV: func() (uint64, uint64, uint64) { return 0, 0, 0 }}
	s := c.Snapshot(context.Background())
	if s.BootID != "process" || s.SampledAt.IsZero() || len(s.Samples) != 14 || len(s.Unavailable) != 5 {
		t.Fatalf("snapshot: %+v", s)
	}
	for _, u := range s.Unavailable[:4] {
		if u.Source != "iface" || u.Metric == "" || u.Dims["interface"] != "missing" {
			t.Fatalf("missing device: %+v", u)
		}
	}
	for _, sample := range s.Samples {
		switch sample.Metric {
		case wire.IfaceRxBytes, wire.IfaceTxBytes, wire.IfaceRxPackets, wire.IfaceTxPackets:
			if sample.Value != 0 || sample.Epoch != "kernel:ns:7" || sample.Dims["interface"] != "eth0" {
				t.Fatal(sample)
			}
		case wire.ProtoPackets, wire.ProtoBytes:
			if sample.Epoch != "process:"+tracker.Generation() {
				t.Fatal(sample)
			}
		default:
			if sample.Value != 0 || sample.Epoch != "process" {
				t.Fatal(sample)
			}
		}
	}
}

func TestSnapshotNotApplied(t *testing.T) {
	s := (Collector{BootID: "p"}).Snapshot(context.Background())
	if len(s.Samples) != 0 || len(s.Unavailable) != 5 {
		t.Fatal(s)
	}
	for _, u := range s.Unavailable[:2] {
		if u.Reason != "interfaces not applied" || u.Metric != "" || len(u.Dims) != 0 {
			t.Fatal(u)
		}
	}
}

func TestMembershipRoles(t *testing.T) {
	m := Bind([]config.Interface{{Name: "uplink", Device: "eth0"}, {Name: "vlan", Type: "vlan", Parent: "uplink"}, {Name: "port", Device: "eth1"}, {Name: "bridge", Type: "bridge", Members: []string{"eth1"}}})
	for i, role := range []string{"parent", "leaf", "parent", "leaf"} {
		if m.Interfaces[i].Role != role {
			t.Fatalf("%+v", m.Interfaces)
		}
	}
}

func TestTrackerEpochChangesOnlyOnRebuild(t *testing.T) {
	a, b := stats.New(), stats.New()
	c := Collector{BootID: "boot", Tracker: func() *stats.Tracker { return a }}
	a.RecordPacket(netip.Addr{}, netip.Addr{}, "tcp", 0, time.Now())
	first := c.Snapshot(context.Background()).Samples[0].Epoch
	if got := c.Snapshot(context.Background()).Samples[0].Epoch; got != first {
		t.Fatal("epoch changed without rebuild")
	}
	a = b
	a.RecordPacket(netip.Addr{}, netip.Addr{}, "tcp", 0, time.Now())
	if got := c.Snapshot(context.Background()).Samples[0].Epoch; got == first {
		t.Fatal("rebuild reused epoch")
	}
	c.BootID = "other"
	if got := c.Snapshot(context.Background()).Samples[0].Epoch; got == first {
		t.Fatal("boot reused epoch")
	}
}

func TestMembershipAccountingLeavesOnly(t *testing.T) {
	m := Bind([]config.Interface{
		{Name: "uplink", Device: "eth0", Zone: "wan"},
		{Name: "vlan", Type: "vlan", Parent: "uplink", Zone: "vlan"},
		{Name: "port", Device: "eth1", Zone: "member"},
		{Name: "bridge", Type: "bridge", Members: []string{"eth1"}, Zone: "lan"},
		{Name: "unbound"},
	})
	zones := m.Zones()
	if len(zones) != 2 || zones["vlan"] != "vlan" || zones["bridge"] != "lan" {
		t.Fatalf("accounting includes a parent or unzoned device: %+v", zones)
	}
}
