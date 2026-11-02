// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

func TestSnapshotDemoSamplesDoNotChangeRealSources(t *testing.T) {
	c := Collector{
		BootID: "boot",
		Events: func() []wire.EventCounts {
			return []wire.EventCounts{{Origin: wire.OriginReal, Total: 7}, {Origin: wire.OriginDemo, Total: 99}}
		},
	}
	before := c.Snapshot(context.Background())
	demo := []wire.CounterSample{{Metric: wire.ProtoPackets, Value: 42, Epoch: "run", Origin: wire.OriginDemo}}
	c.Demo = func() []wire.CounterSample { return demo }
	after := c.Snapshot(context.Background())
	if !reflect.DeepEqual(before.Unavailable, after.Unavailable) ||
		!reflect.DeepEqual(before.Samples, after.Samples[:len(before.Samples)]) ||
		!reflect.DeepEqual(demo, after.Samples[len(before.Samples):]) {
		t.Fatalf("demo changed real collector results: before=%+v after=%+v", before, after)
	}
	for _, s := range before.Samples {
		if s.Origin == wire.OriginDemo {
			t.Fatal("retained demo event totals published without a running replay")
		}
	}
	c.Demo = func() []wire.CounterSample { return nil }
	stopped := c.Snapshot(context.Background())
	if !reflect.DeepEqual(before.Samples, stopped.Samples) || !reflect.DeepEqual(before.Unavailable, stopped.Unavailable) {
		t.Fatal("stopping demo changed real collection or unavailability")
	}
}

func TestSnapshotQuietAndNotConnectedSeries(t *testing.T) {
	tracker := stats.New()
	tracker.RecordPacket(netip.Addr{}, netip.Addr{}, "modbus", 0, time.Now())
	m := Bind([]config.Interface{{Name: "logical", Device: "eth0", Zone: "plant"}, {Name: "missing", Zone: "wan"}})
	c := Collector{BootID: "process", Membership: func() *Membership { return m }, Tracker: func() *stats.Tracker { return tracker }, Link: func(d string) (Link, error) {
		if d == "missing" {
			return Link{}, fs.ErrNotExist
		}
		return Link{Epoch: "kernel:ns:7"}, nil
	}, Events: func() []wire.EventCounts { return []wire.EventCounts{{Origin: wire.OriginReal}} }, AV: func() (uint64, uint64, uint64) { return 0, 0, 0 }}
	s := c.Snapshot(context.Background())
	if s.BootID != "process" || s.SampledAt.IsZero() || len(s.Samples) != 14 || len(s.Unavailable) != 1 {
		t.Fatalf("snapshot: %+v", s)
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

func TestSnapshotLinkFailures(t *testing.T) {
	readFailure := &os.PathError{
		Op:   "open",
		Path: "/sys/class/net/eth2/statistics/rx_bytes",
		Err:  errors.New("read failed"),
	}
	tests := []struct {
		name            string
		devices         []string
		read            func(string) (Link, error)
		wantSamples     map[string]int
		wantUnavailable map[string]string
	}{
		{
			name:    "missing device",
			devices: []string{"eth0"},
			read: func(string) (Link, error) {
				return Link{}, fs.ErrNotExist
			},
			wantSamples:     map[string]int{},
			wantUnavailable: map[string]string{},
		},
		{
			name:    "unreadable existing device",
			devices: []string{"eth0"},
			read: func(string) (Link, error) {
				return Link{}, readFailure
			},
			wantSamples:     map[string]int{},
			wantUnavailable: map[string]string{"eth0": "interface eth0: statistics unreadable: read failed"},
		},
		{
			name:    "missing statistic on existing device",
			devices: []string{"eth0"},
			read: func(string) (Link, error) {
				return Link{}, &linkReadError{err: fs.ErrNotExist}
			},
			wantSamples:     map[string]int{},
			wantUnavailable: map[string]string{"eth0": "interface eth0: statistics unreadable: " + fs.ErrNotExist.Error()},
		},
		{
			name:    "mixed devices",
			devices: []string{"eth0", "eth1", "eth2"},
			read: func(device string) (Link, error) {
				switch device {
				case "eth1":
					return Link{}, fs.ErrNotExist
				case "eth2":
					return Link{}, readFailure
				default:
					return Link{Epoch: "boot:ns:1"}, nil
				}
			},
			wantSamples:     map[string]int{"eth0": 4},
			wantUnavailable: map[string]string{"eth2": "interface eth2: statistics unreadable: read failed"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ifaces := make([]config.Interface, 0, len(tt.devices))
			for _, device := range tt.devices {
				ifaces = append(ifaces, config.Interface{Name: device, Device: device})
			}
			membership := Bind(ifaces)
			snapshot := (Collector{
				Membership: func() *Membership { return membership },
				Link:       tt.read,
				Conduits:   func(context.Context) ([]wire.CounterSample, []wire.SourceUnavailable) { return nil, nil },
				Tracker:    func() *stats.Tracker { return stats.New() },
				Events:     func() []wire.EventCounts { return nil },
				AV:         func() (uint64, uint64, uint64) { return 0, 0, 0 },
			}).Snapshot(context.Background())

			samplesByInterface := make(map[string]int)
			for _, sample := range snapshot.Samples {
				if sample.Metric != wire.IfaceRxBytes && sample.Metric != wire.IfaceTxBytes &&
					sample.Metric != wire.IfaceRxPackets && sample.Metric != wire.IfaceTxPackets {
					continue
				}
				samplesByInterface[sample.Dims["interface"]]++
			}
			if len(samplesByInterface) != len(tt.wantSamples) {
				t.Fatalf("interface sample counts = %v, want %v", samplesByInterface, tt.wantSamples)
			}
			for device, want := range tt.wantSamples {
				if samplesByInterface[device] != want {
					t.Errorf("samples for %s = %d, want %d", device, samplesByInterface[device], want)
				}
			}

			unavailableByInterface := make(map[string][]wire.SourceUnavailable)
			for _, unavailable := range snapshot.Unavailable {
				if unavailable.Source == "iface" {
					device := unavailable.Dims["interface"]
					unavailableByInterface[device] = append(unavailableByInterface[device], unavailable)
				}
			}
			if len(unavailableByInterface) != len(tt.wantUnavailable) {
				t.Fatalf("interface unavailable = %v, want %v", unavailableByInterface, tt.wantUnavailable)
			}
			for device, wantReason := range tt.wantUnavailable {
				entries := unavailableByInterface[device]
				if len(entries) != 4 {
					t.Errorf("unavailable entries for %s = %d, want 4: %+v", device, len(entries), entries)
					continue
				}
				metrics := make(map[wire.Metric]bool, len(entries))
				for _, entry := range entries {
					if entry.Reason != wantReason {
						t.Errorf("reason for %s = %q, want %q", device, entry.Reason, wantReason)
					}
					if entry.Metric == "" {
						t.Errorf("unavailable entry has no metric: %+v", entry)
					}
					if metrics[entry.Metric] {
						t.Errorf("duplicate unavailable metric for %s: %s", device, entry.Metric)
					}
					metrics[entry.Metric] = true
				}
				if len(metrics) != 4 {
					t.Errorf("unavailable metrics for %s = %v, want 4 distinct metrics", device, metrics)
				}
			}
		})
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
