// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

// Collector reads immutable published views through callbacks, never policy locks.
type Collector struct {
	// Demo returns only currently running replay samples; faults stay in simulation status.
	Demo       func() []wire.CounterSample
	BootID     string
	Membership func() *Membership
	Link       func(string) (Link, error)
	Tracker    func() *stats.Tracker
	Events     func() []wire.EventCounts
	AV         func() (uint64, uint64, uint64)
	Conduits   func(context.Context) ([]wire.CounterSample, []wire.SourceUnavailable)
}

// Snapshot includes quiet series and explicit failures rather than invented zeroes.
func (c Collector) Snapshot(ctx context.Context) wire.CounterSnapshot {
	s := wire.CounterSnapshot{BootID: c.BootID, SampledAt: time.Now().UTC(), Samples: []wire.CounterSample{}}
	add := func(metric wire.Metric, dims map[string]string, value uint64, epoch string, origin wire.Origin) {
		s.Samples = append(s.Samples, wire.CounterSample{Metric: metric, Dims: dims, Value: value, Epoch: epoch, Origin: origin})
	}
	missing := func(source, reason string) {
		s.Unavailable = append(s.Unavailable, wire.SourceUnavailable{Source: source, Reason: reason})
	}
	var m *Membership
	if c.Membership != nil {
		m = c.Membership()
	}
	if m == nil {
		missing("iface", "interfaces not applied")
		missing("conduit", "interfaces not applied")
	} else {
		read := c.Link
		if read == nil {
			read = ReadLink
		}
		for _, i := range m.Interfaces {
			dims := map[string]string{"interface": i.Device, "zone": i.Zone, "role": i.Role}
			l, err := read(i.Device)
			if err != nil {
				var existingDeviceErr *linkReadError
				if !errors.As(err, &existingDeviceErr) && errors.Is(err, fs.ErrNotExist) {
					continue
				}
				reason := fmt.Sprintf("interface %s: statistics unreadable: %s", i.Device, shortLinkError(err))
				for _, metric := range []wire.Metric{wire.IfaceRxBytes, wire.IfaceTxBytes, wire.IfaceRxPackets, wire.IfaceTxPackets} {
					s.Unavailable = append(s.Unavailable, wire.SourceUnavailable{Source: "iface", Metric: metric, Dims: dims, Reason: reason})
				}
				continue
			}
			for _, v := range []struct {
				metric wire.Metric
				value  uint64
			}{{wire.IfaceRxBytes, l.RxBytes}, {wire.IfaceTxBytes, l.TxBytes}, {wire.IfaceRxPackets, l.RxPackets}, {wire.IfaceTxPackets, l.TxPackets}} {
				add(v.metric, dims, v.value, l.Epoch, wire.OriginReal)
			}
		}
		if c.Conduits == nil {
			missing("conduit", "accounting unavailable")
		} else {
			samples, unavailable := c.Conduits(ctx)
			s.Samples = append(s.Samples, samples...)
			s.Unavailable = append(s.Unavailable, unavailable...)
		}
	}
	var tracker *stats.Tracker
	if c.Tracker != nil {
		tracker = c.Tracker()
	}
	if tracker == nil {
		missing("proto", "tracker unavailable")
	} else {
		epoch := c.BootID + ":" + tracker.Generation()
		for _, p := range tracker.Stats() {
			dims := map[string]string{"protocol": p.Protocol}
			if p.PacketCount < 0 || p.ByteCount < 0 {
				for _, metric := range []wire.Metric{wire.ProtoPackets, wire.ProtoBytes} {
					s.Unavailable = append(s.Unavailable, wire.SourceUnavailable{Source: "proto", Metric: metric, Dims: dims, Reason: "counter overflow"})
				}
				continue
			}
			add(wire.ProtoPackets, dims, uint64(p.PacketCount), epoch, wire.OriginReal)
			add(wire.ProtoBytes, dims, uint64(p.ByteCount), epoch, wire.OriginReal)
		}
	}
	if c.Events == nil {
		missing("events", "event store unavailable")
	} else {
		for _, e := range c.Events() {
			if e.Origin == wire.OriginDemo {
				continue // demo events use the replay run epoch, only while running
			}
			add(wire.EventsTotal, map[string]string{"source": "engine"}, e.Total, c.BootID, e.Origin)
			for _, class := range []wire.EventClass{wire.ClassIDSAlert, wire.ClassAVDetection, wire.ClassAVBlock, wire.ClassModbusWrite} {
				add(wire.EventsClass, map[string]string{"source": "engine", "class": string(class)}, e.Classes[class], c.BootID, e.Origin)
			}
		}
	}
	if c.AV == nil {
		missing("av", "antivirus unavailable")
	} else {
		scans, errors, detections := c.AV()
		add(wire.AVScans, nil, scans, c.BootID, wire.OriginReal)
		add(wire.AVScanErrors, nil, errors, c.BootID, wire.OriginReal)
		add(wire.AVDetections, nil, detections, c.BootID, wire.OriginReal)
	}
	if c.Demo != nil {
		s.Samples = append(s.Samples, c.Demo()...)
	}
	return s
}

func shortLinkError(err error) string {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) && pathErr.Err != nil {
		return pathErr.Err.Error()
	}
	return err.Error()
}
