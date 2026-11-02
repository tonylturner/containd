// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package telemetry holds the wire types of retained counter history: the
// engine's counter snapshot that management samples, and the public series
// that charts read. Storage and sampling live in pkg/cp/telemetry.
package telemetry

import (
	"context"
	"time"
)

// Origin separates real traffic from demo replay. Demo counters never charge
// real series, and real series never include demo traffic.
type Origin string

const (
	OriginReal Origin = "real"
	OriginDemo Origin = "demo"
)

// Unit is what one counter increment counts.
type Unit string

const (
	UnitBytes   Unit = "bytes"
	UnitPackets Unit = "packets"
	UnitEvents  Unit = "events"
	UnitScans   Unit = "scans"
)

// Metric names a monotonic counter. Every metric has a fixed unit and a
// fixed, bounded set of dimension keys.
type Metric string

const (
	// Kernel link statistics of config-bound interfaces. Dims: interface
	// (kernel device), zone (from the running config when sampled).
	IfaceRxBytes   Metric = "iface.rx_bytes"
	IfaceTxBytes   Metric = "iface.tx_bytes"
	IfaceRxPackets Metric = "iface.rx_packets"
	IfaceTxPackets Metric = "iface.tx_packets"

	// Forwarded traffic that passed policy, per zone pair. Dims: from, to.
	ConduitBytes   Metric = "conduit.bytes"
	ConduitPackets Metric = "conduit.packets"

	// Traffic the engine inspected, per protocol. Dims: protocol.
	ProtoPackets Metric = "proto.packets"
	ProtoBytes   Metric = "proto.bytes"

	// Events appended to an event store. Dims: source (engine|services).
	EventsTotal Metric = "events.total"
	// Events matching one class predicate. Dims: source, class (EventClass).
	EventsClass Metric = "events.class"

	// Management service meters. Dims: service.
	ServiceEvents Metric = "service.events"
	ServiceErrors Metric = "service.errors"

	// Engine antivirus. No dims.
	AVScans      Metric = "av.scans"
	AVScanErrors Metric = "av.scan_errors"
	AVDetections Metric = "av.detections"
)

// MetricUnits is the unit of every metric. A metric not listed here is not
// part of the contract.
var MetricUnits = map[Metric]Unit{
	IfaceRxBytes: UnitBytes, IfaceTxBytes: UnitBytes,
	IfaceRxPackets: UnitPackets, IfaceTxPackets: UnitPackets,
	ConduitBytes: UnitBytes, ConduitPackets: UnitPackets,
	ProtoPackets: UnitPackets, ProtoBytes: UnitBytes,
	EventsTotal: UnitEvents, EventsClass: UnitEvents,
	ServiceEvents: UnitEvents, ServiceErrors: UnitEvents,
	AVScans: UnitScans, AVScanErrors: UnitScans, AVDetections: UnitEvents,
}

// EventClass is one events.class predicate. An event can match several.
type EventClass string

const (
	ClassIDSAlert    EventClass = "ids_alert"    // proto "ids", kind "alert"
	ClassAVDetection EventClass = "av_detection" // kind "service.av.detected"
	ClassAVBlock     EventClass = "av_block"     // kind "service.av.block_flow"
	ClassModbusWrite EventClass = "modbus_write" // modbus request with a write function code
)

// CounterSample is one cumulative counter reading.
type CounterSample struct {
	Metric Metric            `json:"metric"`
	Dims   map[string]string `json:"dims,omitempty"`
	// Value is the cumulative count since the counter last started from zero.
	Value uint64 `json:"value,string"`
	// Epoch changes whenever this counter may have restarted from zero
	// (process boot, tracker rebuild, interface recreation, accounting table
	// rebuild). Opaque; compare for equality only.
	Epoch string `json:"epoch"`
}

// SourceUnavailable says why a whole source has no samples in a snapshot.
// A missing source is a gap, never zero.
type SourceUnavailable struct {
	Source string `json:"source"` // iface, conduit, proto, events, av
	Reason string `json:"reason"`
}

// CounterSnapshot is the engine's GET /internal/telemetry/counters body.
type CounterSnapshot struct {
	Origin      Origin              `json:"origin"`
	BootID      string              `json:"bootId"`
	SampledAt   time.Time           `json:"sampledAt"`
	Samples     []CounterSample     `json:"samples"`
	Unavailable []SourceUnavailable `json:"unavailable,omitempty"`
}

// CounterReader reads one counter snapshot. The engine HTTP client and the
// management-local sources implement it.
type CounterReader interface {
	TelemetryCounters(ctx context.Context) (CounterSnapshot, error)
}

// Quality says how much of a bucket was observed.
type Quality string

const (
	// Observed: the whole bucket was sampled; V is the exact count.
	QualityObserved Quality = "observed"
	// Partial: part of the bucket was sampled; V counts the observed part.
	QualityPartial Quality = "partial"
	// Reset: a counter restarted inside the bucket; V counts what was
	// observed, including the count since the restart.
	QualityReset Quality = "reset"
	// Gap: nothing was sampled; V is absent.
	QualityGap Quality = "gap"
)

// Point is one bucket of a series.
type Point struct {
	T time.Time `json:"t"` // bucket start
	// V is the count in the bucket as a decimal string; absent for a gap.
	V *uint64 `json:"v,string,omitempty"`
	Q Quality `json:"q"`
}

// Series is one dimension combination of a metric.
type Series struct {
	Dims   map[string]string `json:"dims,omitempty"`
	Points []Point           `json:"points"`
}

// Range is a query window; each range has one fixed resolution.
type Range string

const (
	Range1h  Range = "1h"  // 10 s buckets
	Range24h Range = "24h" // 1 min buckets
	Range30d Range = "30d" // 15 min buckets
)

// RangeResolution is the bucket width of each range.
var RangeResolution = map[Range]time.Duration{
	Range1h:  10 * time.Second,
	Range24h: time.Minute,
	Range30d: 15 * time.Minute,
}

// CollectorState describes the sampler, separately from any series.
type CollectorState struct {
	State        string    `json:"state"` // running, stalled, unavailable
	LastSampleAt time.Time `json:"lastSampleAt,omitzero"`
	Error        string    `json:"error,omitempty"`
}

// SeriesResponse is the GET /api/v1/telemetry/series body.
type SeriesResponse struct {
	Metric            Metric    `json:"metric"`
	Unit              Unit      `json:"unit"`
	Origin            Origin    `json:"origin"`
	Range             Range     `json:"range"`
	ResolutionSeconds int       `json:"resolutionSeconds"`
	From              time.Time `json:"from"`
	To                time.Time `json:"to"`
	// RealObserved is true once any real observed bucket of this metric
	// counted more than zero. Charts show demo series only while it is false.
	RealObserved bool `json:"realObserved"`
	// RetainedFrom is the oldest bucket still stored at this resolution.
	RetainedFrom time.Time      `json:"retainedFrom,omitzero"`
	Collector    CollectorState `json:"collector"`
	Series       []Series       `json:"series"`
}
