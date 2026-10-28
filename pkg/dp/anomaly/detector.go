// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package anomaly

import (
	"fmt"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Anomaly represents a detected protocol-level anomaly in ICS traffic.
type Anomaly struct {
	Type       string         `json:"type"`     // malformed_frame, protocol_violation, rate_anomaly
	Protocol   string         `json:"protocol"` // modbus, dnp3, cip
	Severity   string         `json:"severity"` // low, medium, high, critical
	Message    string         `json:"message"`
	SourceIP   string         `json:"source_ip"`
	DestIP     string         `json:"dest_ip"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
}

// Option configures a Detector.
type Option func(*Detector)

// WithWriteRateThreshold sets the maximum write operations per minute per flow
// before a rate anomaly is raised.
func WithWriteRateThreshold(perMinute int) Option {
	return func(d *Detector) {
		d.writeRateThreshold = perMinute
	}
}

// WithTotalRateThreshold sets the maximum total operations per minute per flow
// before a rate anomaly is raised.
func WithTotalRateThreshold(perMinute int) Option {
	return func(d *Detector) {
		d.totalRateThreshold = perMinute
	}
}

// WithDNP3RestartFromNonMaster controls whether cold/warm restart from
// non-master direction is flagged. Default: true.
func WithDNP3RestartFromNonMaster(enable bool) Option {
	return func(d *Detector) {
		d.dnp3RestartFromNonMaster = enable
	}
}

// WithCIPProgramChangeDetection controls whether CIP program mode changes
// are flagged. Default: true.
func WithCIPProgramChangeDetection(enable bool) Option {
	return func(d *Detector) {
		d.cipProgramChangeDetection = enable
	}
}

const (
	defaultWriteRateThreshold = 100
	defaultTotalRateThreshold = 1000
	ringSize                  = 4096
)

// Detector is the protocol anomaly detection engine.
type Detector struct {
	mu                 sync.Mutex
	writeRateThreshold int
	totalRateThreshold int

	// Feature toggles (all default to true).
	dnp3RestartFromNonMaster  bool
	cipProgramChangeDetection bool

	// Per-flow tracking of last transaction IDs (for Modbus request/response pairing).
	// Key: "srcIP->dstIP"
	pendingTxns map[string]map[uint16]bool // flow -> set of pending transaction IDs

	writeRate *rateTracker
	totalRate *rateTracker

	// IEC104 APDU IDs already counted for rates (bounded).
	apduSeen  map[string]struct{}
	apduOrder []string

	// Ring buffer of recent anomalies.
	ring    []Anomaly
	ringPos int
	ringLen int
}

// New creates a new anomaly Detector with the given options.
func New(opts ...Option) *Detector {
	d := &Detector{
		writeRateThreshold:        defaultWriteRateThreshold,
		totalRateThreshold:        defaultTotalRateThreshold,
		dnp3RestartFromNonMaster:  true,
		cipProgramChangeDetection: true,
		pendingTxns:               make(map[string]map[uint16]bool),
		writeRate:                 newRateTracker(),
		totalRate:                 newRateTracker(),
		apduSeen:                  make(map[string]struct{}),
		ring:                      make([]Anomaly, ringSize),
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

func flowKey(srcIP, dstIP string) string {
	return srcIP + "->" + dstIP
}

// Check inspects a DPI event for protocol anomalies and returns any detected.
func (d *Detector) Check(srcIP, dstIP string, ev dpi.Event) []Anomaly {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []Anomaly

	// 1. Malformed frame detection: look for error attributes set by decoders.
	if errMsg, ok := ev.Attributes["error"].(string); ok && errMsg != "" {
		a := Anomaly{
			Type:     "malformed_frame",
			Protocol: ev.Proto,
			Severity: "medium",
			Message:  fmt.Sprintf("Malformed frame: %s", errMsg),
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"error": errMsg,
			},
			Timestamp: ev.Timestamp,
		}
		out = append(out, a)
	}

	// 2. Protocol-specific violations.
	switch ev.Proto {
	case "modbus":
		out = append(out, d.checkModbus(srcIP, dstIP, ev)...)
	case "dnp3":
		out = append(out, d.checkDNP3(srcIP, dstIP, ev)...)
	case "cip":
		out = append(out, d.checkCIP(srcIP, dstIP, ev)...)
	case "iec104":
		out = append(out, d.checkIEC104(srcIP, dstIP, ev)...)
	}

	// 3. Rate anomalies, counted once per APDU.
	if !d.countsForRate(ev) {
		for _, a := range out {
			d.recordAnomaly(a)
		}
		return out
	}
	fk := flowKey(srcIP, dstIP)

	totalCount := d.totalRate.record(fk)
	if totalCount > d.totalRateThreshold {
		a := Anomaly{
			Type:     "rate_anomaly",
			Protocol: ev.Proto,
			Severity: "high",
			Message:  fmt.Sprintf("Total operation rate %d/min exceeds threshold %d/min", totalCount, d.totalRateThreshold),
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"rate":      totalCount,
				"threshold": d.totalRateThreshold,
				"kind":      "total",
			},
			Timestamp: ev.Timestamp,
		}
		out = append(out, a)
	}

	if isWrite, ok := ev.Attributes["is_write"].(bool); ok && isWrite {
		writeKey := fk + ":write"
		writeCount := d.writeRate.record(writeKey)
		if writeCount > d.writeRateThreshold {
			a := Anomaly{
				Type:     "rate_anomaly",
				Protocol: ev.Proto,
				Severity: "critical",
				Message:  fmt.Sprintf("Write operation rate %d/min exceeds threshold %d/min", writeCount, d.writeRateThreshold),
				SourceIP: srcIP,
				DestIP:   dstIP,
				Attributes: map[string]any{
					"rate":      writeCount,
					"threshold": d.writeRateThreshold,
					"kind":      "write",
				},
				Timestamp: ev.Timestamp,
			}
			out = append(out, a)
		}
	}

	// Record all anomalies in the ring buffer.
	for _, a := range out {
		d.recordAnomaly(a)
	}

	return out
}

func (d *Detector) checkModbus(srcIP, dstIP string, ev dpi.Event) []Anomaly {
	var out []Anomaly

	fc, hasFC := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode)
	txnID, hasTxn := eventfields.Uint16(ev.Attributes, "transaction_id")
	unitID, hasUnit := eventfields.Uint8(ev.Attributes, eventfields.KeyUnitID)
	isWrite, _ := eventfields.Bool(ev.Attributes, eventfields.KeyIsWrite)

	// Invalid function code: >= 128 in a request indicates an exception code
	// being used as a request function code, which is a protocol violation.
	if ev.Kind == "request" && hasFC && fc >= 128 {
		out = append(out, Anomaly{
			Type:     "protocol_violation",
			Protocol: "modbus",
			Severity: "high",
			Message:  fmt.Sprintf("Invalid Modbus function code %d in request", fc),
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"function_code": fc,
			},
			Timestamp: ev.Timestamp,
		})
	}

	// Broadcast unit ID 0 for write operations is suspicious.
	if hasUnit && unitID == 0 && isWrite {
		out = append(out, Anomaly{
			Type:     "protocol_violation",
			Protocol: "modbus",
			Severity: "high",
			Message:  "Broadcast unit ID 0 used for write operation",
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"unit_id":       unitID,
				"function_code": fc,
			},
			Timestamp: ev.Timestamp,
		})
	}

	// Track transaction IDs for request/response pairing.
	if hasTxn {
		fk := flowKey(srcIP, dstIP)
		reverseFk := flowKey(dstIP, srcIP)

		if ev.Kind == "request" {
			if d.pendingTxns[fk] == nil {
				d.pendingTxns[fk] = make(map[uint16]bool)
			}
			d.pendingTxns[fk][txnID] = true
		} else if ev.Kind == "response" || (ev.Kind == "exception" && isModbusExceptionReply(ev, srcIP, dstIP)) {
			// A response should match a prior request on the reverse flow.
			pending := d.pendingTxns[reverseFk]
			if pending == nil || !pending[txnID] {
				replyKind := "response"
				if ev.Kind == "exception" {
					replyKind = "exception"
				}
				out = append(out, Anomaly{
					Type:     "protocol_violation",
					Protocol: "modbus",
					Severity: "medium",
					Message:  fmt.Sprintf("Modbus %s (txn %d) without prior request", replyKind, txnID),
					SourceIP: srcIP,
					DestIP:   dstIP,
					Attributes: map[string]any{
						"transaction_id": txnID,
					},
					Timestamp: ev.Timestamp,
				})
			} else {
				delete(pending, txnID)
			}
		}
	}

	return out
}

func isModbusExceptionReply(ev dpi.Event, srcIP, dstIP string) bool {
	key, ok := flow.ParseKey(ev.FlowID)
	return ok &&
		key.Dir == flow.DirReverse &&
		key.SrcIP.String() == srcIP &&
		key.DstIP.String() == dstIP
}

// recordAnomaly adds an anomaly to the ring buffer (must be called under lock).
func (d *Detector) recordAnomaly(a Anomaly) {
	d.ring[d.ringPos] = a
	d.ringPos = (d.ringPos + 1) % ringSize
	if d.ringLen < ringSize {
		d.ringLen++
	}
}

// Anomalies returns recent anomalies, up to limit. If limit <= 0, all buffered
// anomalies are returned.
func (d *Detector) Anomalies(limit int) []Anomaly {
	d.mu.Lock()
	defer d.mu.Unlock()

	n := d.ringLen
	if limit > 0 && limit < n {
		n = limit
	}
	if n == 0 {
		return nil
	}

	out := make([]Anomaly, n)
	// Return most recent first.
	for i := 0; i < n; i++ {
		idx := (d.ringPos - 1 - i + ringSize) % ringSize
		out[i] = d.ring[idx]
	}
	return out
}

// Clear resets all state in the detector.
func (d *Detector) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.pendingTxns = make(map[string]map[uint16]bool)
	d.writeRate = newRateTracker()
	d.totalRate = newRateTracker()
	d.apduSeen = make(map[string]struct{})
	d.apduOrder = nil
	d.ring = make([]Anomaly, ringSize)
	d.ringPos = 0
	d.ringLen = 0
}

func (d *Detector) checkDNP3(srcIP, dstIP string, ev dpi.Event) []Anomaly {
	var out []Anomaly

	fc, hasFC := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode)
	if !hasFC {
		return nil
	}
	direction, _ := eventfields.String(ev.Attributes, eventfields.KeyDirection)

	if d.dnp3RestartFromNonMaster {
		// Cold restart (FC 13) or warm restart (FC 14) from non-master direction.
		if (fc == 13 || fc == 14) && direction != "master" {
			label := "Cold"
			if fc == 14 {
				label = "Warm"
			}
			out = append(out, Anomaly{
				Type:     "protocol_violation",
				Protocol: "dnp3",
				Severity: "critical",
				Message:  fmt.Sprintf("DNP3 %s restart (FC %d) from non-master direction", label, fc),
				SourceIP: srcIP,
				DestIP:   dstIP,
				Attributes: map[string]any{
					"function_code": fc,
					"direction":     direction,
				},
				Timestamp: ev.Timestamp,
			})
		}

		// Unsolicited response (FC 130) without prior enable unsolicited (FC 20).
		if fc == 130 {
			out = append(out, Anomaly{
				Type:     "protocol_violation",
				Protocol: "dnp3",
				Severity: "high",
				Message:  "DNP3 unsolicited response (FC 130) detected",
				SourceIP: srcIP,
				DestIP:   dstIP,
				Attributes: map[string]any{
					"function_code": fc,
				},
				Timestamp: ev.Timestamp,
			})
		}
	}

	// Invalid function codes in requests: valid request FCs are 0-33 and 129-131.
	if ev.Kind == "request" {
		if (fc > 33 && fc < 129) || fc > 131 {
			out = append(out, Anomaly{
				Type:     "protocol_violation",
				Protocol: "dnp3",
				Severity: "high",
				Message:  fmt.Sprintf("Invalid DNP3 function code %d in request", fc),
				SourceIP: srcIP,
				DestIP:   dstIP,
				Attributes: map[string]any{
					"function_code": fc,
				},
				Timestamp: ev.Timestamp,
			})
		}
	}

	return out
}

func (d *Detector) checkCIP(srcIP, dstIP string, ev dpi.Event) []Anomaly {
	var out []Anomaly

	if !d.cipProgramChangeDetection {
		return nil
	}

	service, hasService := eventfields.Uint8(ev.Attributes, "service_code")

	// Program mode change: Stop (0x07), Start/Run (0x06).
	switch {
	case hasService && service == 0x07: // Stop
		out = append(out, Anomaly{
			Type:     "protocol_violation",
			Protocol: "cip",
			Severity: "critical",
			Message:  "CIP Program Stop command detected (service 0x07)",
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"service_code": service,
			},
			Timestamp: ev.Timestamp,
		})
	case hasService && service == 0x06: // Start/Run
		out = append(out, Anomaly{
			Type:     "protocol_violation",
			Protocol: "cip",
			Severity: "high",
			Message:  "CIP Program Start command detected (service 0x06)",
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"service_code": service,
			},
			Timestamp: ev.Timestamp,
		})
	}

	// Forward Open from unexpected sources.
	if ev.Kind == "forward_open" {
		out = append(out, Anomaly{
			Type:     "protocol_violation",
			Protocol: "cip",
			Severity: "medium",
			Message:  "CIP Forward Open detected",
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"kind": ev.Kind,
			},
			Timestamp: ev.Timestamp,
		})
	}

	return out
}

// rateTracker tracks events per minute per key using minute-granularity buckets.
type rateTracker struct {
	// key -> minute-bucket -> count
	buckets map[string]map[int64]int
}

func newRateTracker() *rateTracker {
	return &rateTracker{
		buckets: make(map[string]map[int64]int),
	}
}

// record adds an event for key at the current time and returns the rate
// (events in the last minute).
func (rt *rateTracker) record(key string) int {
	now := time.Now()
	currentMinute := now.Unix() / 60

	if rt.buckets[key] == nil {
		rt.buckets[key] = make(map[int64]int)
	}
	rt.buckets[key][currentMinute]++

	// Sum events in the current minute bucket.
	count := rt.buckets[key][currentMinute]

	// Also include the previous minute, prorated.
	prevMinute := currentMinute - 1
	if prev, ok := rt.buckets[key][prevMinute]; ok {
		// Simple approach: add previous minute's full count for a sliding window.
		count += prev
	}

	// Garbage-collect old buckets (keep last 5 minutes).
	cutoff := currentMinute - 5
	for m := range rt.buckets[key] {
		if m < cutoff {
			delete(rt.buckets[key], m)
		}
	}

	return count
}

// recordAt is like record but uses a specific time. Used for testing.
func (rt *rateTracker) recordAt(key string, t time.Time) int {
	currentMinute := t.Unix() / 60

	if rt.buckets[key] == nil {
		rt.buckets[key] = make(map[int64]int)
	}
	rt.buckets[key][currentMinute]++

	count := rt.buckets[key][currentMinute]

	prevMinute := currentMinute - 1
	if prev, ok := rt.buckets[key][prevMinute]; ok {
		count += prev
	}

	cutoff := currentMinute - 5
	for m := range rt.buckets[key] {
		if m < cutoff {
			delete(rt.buckets[key], m)
		}
	}

	return count
}
