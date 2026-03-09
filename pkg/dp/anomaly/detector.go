// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package anomaly

import (
	"fmt"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// Anomaly represents a detected protocol-level anomaly in ICS traffic.
type Anomaly struct {
	Type       string         `json:"type"`       // malformed_frame, protocol_violation, rate_anomaly
	Protocol   string         `json:"protocol"`   // modbus, dnp3, cip
	Severity   string         `json:"severity"`   // low, medium, high, critical
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

// WithS7StopDetection controls whether PLC stop commands are flagged.
// Default: true.
func WithS7StopDetection(enable bool) Option {
	return func(d *Detector) {
		d.s7StopDetection = enable
	}
}

// WithCIPProgramChangeDetection controls whether CIP program mode changes
// are flagged. Default: true.
func WithCIPProgramChangeDetection(enable bool) Option {
	return func(d *Detector) {
		d.cipProgramChangeDetection = enable
	}
}

// WithCrossProtocolDetection controls whether multiple ICS protocols on the
// same flow are flagged. Default: true.
func WithCrossProtocolDetection(enable bool) Option {
	return func(d *Detector) {
		d.crossProtocolDetection = enable
	}
}

// WithNonStandardPortDetection controls whether ICS traffic on non-standard
// ports is flagged. Default: true.
func WithNonStandardPortDetection(enable bool) Option {
	return func(d *Detector) {
		d.nonStandardPortDetection = enable
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
	s7StopDetection           bool
	cipProgramChangeDetection bool
	crossProtocolDetection    bool
	nonStandardPortDetection  bool

	// Per-flow tracking of last transaction IDs (for Modbus request/response pairing).
	// Key: "srcIP->dstIP"
	pendingTxns map[string]map[uint16]bool // flow -> set of pending transaction IDs

	// Per-flow ICS protocol tracking for cross-protocol detection.
	// Key: "srcIP->dstIP", value: set of observed ICS protocol names.
	flowProtos map[string]map[string]bool

	writeRate *rateTracker
	totalRate *rateTracker

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
		s7StopDetection:           true,
		cipProgramChangeDetection: true,
		crossProtocolDetection:    true,
		nonStandardPortDetection:  true,
		pendingTxns:               make(map[string]map[uint16]bool),
		flowProtos:                make(map[string]map[string]bool),
		writeRate:                 newRateTracker(),
		totalRate:                 newRateTracker(),
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
	case "s7", "s7comm":
		out = append(out, d.checkS7comm(srcIP, dstIP, ev)...)
	case "cip":
		out = append(out, d.checkCIP(srcIP, dstIP, ev)...)
	}

	// 2b. Cross-protocol violations.
	out = append(out, d.checkCrossProtocol(srcIP, dstIP, ev)...)

	// 3. Rate anomalies.
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

	fc, _ := ev.Attributes["function_code"].(int)
	txnID, hasTxn := ev.Attributes["transaction_id"].(uint16)
	unitID, _ := ev.Attributes["unit_id"].(int)
	isWrite, _ := ev.Attributes["is_write"].(bool)

	// Invalid function code: >= 128 in a request indicates an exception code
	// being used as a request function code, which is a protocol violation.
	if ev.Kind == "request" && fc >= 128 {
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
	if unitID == 0 && isWrite {
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
		} else if ev.Kind == "response" {
			// A response should match a prior request on the reverse flow.
			pending := d.pendingTxns[reverseFk]
			if pending == nil || !pending[txnID] {
				out = append(out, Anomaly{
					Type:     "protocol_violation",
					Protocol: "modbus",
					Severity: "medium",
					Message:  fmt.Sprintf("Modbus response (txn %d) without prior request", txnID),
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
	d.flowProtos = make(map[string]map[string]bool)
	d.writeRate = newRateTracker()
	d.totalRate = newRateTracker()
	d.ring = make([]Anomaly, ringSize)
	d.ringPos = 0
	d.ringLen = 0
}

func (d *Detector) checkDNP3(srcIP, dstIP string, ev dpi.Event) []Anomaly {
	var out []Anomaly

	fc, _ := ev.Attributes["function_code"].(int)
	direction, _ := ev.Attributes["direction"].(string)

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
		if fc < 0 || (fc > 33 && fc < 129) || fc > 131 {
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

func (d *Detector) checkS7comm(srcIP, dstIP string, ev dpi.Event) []Anomaly {
	var out []Anomaly

	if !d.s7StopDetection {
		return nil
	}

	fc, _ := ev.Attributes["function_code"].(int)

	// PLC Stop command (FC 0x29 = 41).
	if fc == 0x29 {
		out = append(out, Anomaly{
			Type:     "protocol_violation",
			Protocol: "s7comm",
			Severity: "critical",
			Message:  "S7comm PLC Stop command detected (FC 0x29)",
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"function_code": fc,
			},
			Timestamp: ev.Timestamp,
		})
	}

	// Control operations: CPU start (0x28), memory write (0x05), download (0x1A, 0x1B).
	switch fc {
	case 0x28: // PLC Start/Run
		out = append(out, Anomaly{
			Type:     "protocol_violation",
			Protocol: "s7comm",
			Severity: "high",
			Message:  "S7comm PLC control operation detected (CPU Start, FC 0x28)",
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"function_code": fc,
			},
			Timestamp: ev.Timestamp,
		})
	case 0x1A, 0x1B: // Download block
		out = append(out, Anomaly{
			Type:     "protocol_violation",
			Protocol: "s7comm",
			Severity: "high",
			Message:  fmt.Sprintf("S7comm download operation detected (FC 0x%02X)", fc),
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"function_code": fc,
			},
			Timestamp: ev.Timestamp,
		})
	}

	return out
}

func (d *Detector) checkCIP(srcIP, dstIP string, ev dpi.Event) []Anomaly {
	var out []Anomaly

	if !d.cipProgramChangeDetection {
		return nil
	}

	service, _ := ev.Attributes["service"].(int)

	// Program mode change: Stop (0x07), Start/Run (0x06).
	switch service {
	case 0x07: // Stop
		out = append(out, Anomaly{
			Type:     "protocol_violation",
			Protocol: "cip",
			Severity: "critical",
			Message:  "CIP Program Stop command detected (service 0x07)",
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"service": service,
			},
			Timestamp: ev.Timestamp,
		})
	case 0x06: // Start/Run
		out = append(out, Anomaly{
			Type:     "protocol_violation",
			Protocol: "cip",
			Severity: "high",
			Message:  "CIP Program Start command detected (service 0x06)",
			SourceIP: srcIP,
			DestIP:   dstIP,
			Attributes: map[string]any{
				"service": service,
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

// checkCrossProtocol detects multiple ICS protocols on the same flow and
// ICS traffic on non-standard ports.
func (d *Detector) checkCrossProtocol(srcIP, dstIP string, ev dpi.Event) []Anomaly {
	var out []Anomaly
	proto := ev.Proto

	// Only track known ICS protocols.
	if !isKnownICS(proto) {
		return nil
	}

	fk := flowKey(srcIP, dstIP)

	// Cross-protocol: multiple different ICS protocols on same flow.
	if d.crossProtocolDetection {
		if d.flowProtos[fk] == nil {
			d.flowProtos[fk] = make(map[string]bool)
		}
		d.flowProtos[fk][proto] = true

		if len(d.flowProtos[fk]) > 1 {
			// Build list of protocols seen.
			var protos []string
			for p := range d.flowProtos[fk] {
				protos = append(protos, p)
			}
			out = append(out, Anomaly{
				Type:     "protocol_violation",
				Protocol: proto,
				Severity: "high",
				Message:  fmt.Sprintf("Multiple ICS protocols on same flow: %v", protos),
				SourceIP: srcIP,
				DestIP:   dstIP,
				Attributes: map[string]any{
					"protocols": protos,
				},
				Timestamp: ev.Timestamp,
			})
		}
	}

	// Non-standard port detection.
	if d.nonStandardPortDetection {
		srcPort, _ := ev.Attributes["src_port"].(uint16)
		dstPort, _ := ev.Attributes["dst_port"].(uint16)
		if srcPort > 0 || dstPort > 0 {
			if !isStandardPort(proto, srcPort) && !isStandardPort(proto, dstPort) {
				out = append(out, Anomaly{
					Type:     "protocol_violation",
					Protocol: proto,
					Severity: "low",
					Message:  fmt.Sprintf("ICS protocol %s on non-standard ports (%d -> %d), possible tunneling", proto, srcPort, dstPort),
					SourceIP: srcIP,
					DestIP:   dstIP,
					Attributes: map[string]any{
						"src_port": srcPort,
						"dst_port": dstPort,
					},
					Timestamp: ev.Timestamp,
				})
			}
		}
	}

	return out
}

func isKnownICS(proto string) bool {
	switch proto {
	case "modbus", "dnp3", "cip", "s7", "s7comm", "bacnet", "opcua", "mms", "iec104":
		return true
	}
	return false
}

func isStandardPort(proto string, port uint16) bool {
	if port == 0 {
		return true // unknown port, don't flag
	}
	switch proto {
	case "modbus":
		return port == 502
	case "dnp3":
		return port == 20000
	case "cip":
		return port == 44818 || port == 2222
	case "s7", "s7comm", "mms":
		return port == 102
	case "bacnet":
		return port == 47808
	case "opcua":
		return port == 4840
	case "iec104":
		return port == 2404
	}
	return true // unknown protocol, don't flag
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
