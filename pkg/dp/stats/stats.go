// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package stats

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// ProtoStats holds per-protocol counters.
type ProtoStats struct {
	Protocol    string    `json:"protocol"`
	PacketCount int64     `json:"packetCount"`
	ByteCount   int64     `json:"byteCount"`
	EventCount  int64     `json:"eventCount"`
	ReadCount   int64     `json:"readCount"`
	WriteCount  int64     `json:"writeCount"`
	AlertCount  int64     `json:"alertCount"`
	LastSeen    time.Time `json:"lastSeen"`
}

// FlowStats holds per-flow counters for top-talker analysis.
type FlowStats struct {
	SrcIP    string `json:"srcIp"`
	DstIP    string `json:"dstIp"`
	Protocol string `json:"protocol"`
	Packets  int64  `json:"packets"`
	Bytes    int64  `json:"bytes"`
}

// Tracker records per-protocol and per-flow statistics from DPI events.
type Tracker struct {
	mu    sync.RWMutex
	proto map[string]*ProtoStats
	flows map[string]*FlowStats
}

// New creates a new statistics tracker.
func New() *Tracker {
	return &Tracker{
		proto: make(map[string]*ProtoStats),
		flows: make(map[string]*FlowStats),
	}
}

// Record updates stats for the event's protocol and flow.
func (t *Tracker) Record(ev dpi.Event, bytes int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	proto := ev.Proto
	if proto == "" {
		proto = "unknown"
	}

	ps, ok := t.proto[proto]
	if !ok {
		ps = &ProtoStats{Protocol: proto}
		t.proto[proto] = ps
	}
	ps.PacketCount++
	ps.ByteCount += int64(bytes)
	ps.EventCount++
	ps.LastSeen = ev.Timestamp

	kind := strings.ToLower(ev.Kind)
	switch {
	case strings.Contains(kind, "alert"):
		ps.AlertCount++
	case attrBool(ev.Attributes, "is_write"):
		ps.WriteCount++
	case strings.Contains(kind, "write"):
		ps.WriteCount++
	default:
		ps.ReadCount++
	}

	// Update flow stats using src/dst from event attributes.
	srcIP := attrStr(ev.Attributes, "src")
	dstIP := attrStr(ev.Attributes, "dst")
	if srcIP != "" && dstIP != "" {
		flowKey := srcIP + "|" + dstIP + "|" + proto
		fs, ok := t.flows[flowKey]
		if !ok {
			fs = &FlowStats{SrcIP: srcIP, DstIP: dstIP, Protocol: proto}
			t.flows[flowKey] = fs
		}
		fs.Packets++
		fs.Bytes += int64(bytes)
	}
}

// RecordFlow updates flow-level stats without requiring a DPI event.
// Useful for recording packet/byte counters from flow state.
func (t *Tracker) RecordFlow(srcIP, dstIP, protocol string, packets, bytes int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if protocol == "" {
		protocol = "unknown"
	}
	flowKey := srcIP + "|" + dstIP + "|" + protocol
	fs, ok := t.flows[flowKey]
	if !ok {
		fs = &FlowStats{SrcIP: srcIP, DstIP: dstIP, Protocol: protocol}
		t.flows[flowKey] = fs
	}
	fs.Packets += packets
	fs.Bytes += bytes
}

// Stats returns all protocol statistics sorted by packet count descending.
func (t *Tracker) Stats() []ProtoStats {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]ProtoStats, 0, len(t.proto))
	for _, ps := range t.proto {
		out = append(out, *ps)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PacketCount > out[j].PacketCount
	})
	return out
}

// TopTalkers returns the top N flows by byte count descending.
func (t *Tracker) TopTalkers(n int) []FlowStats {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]FlowStats, 0, len(t.flows))
	for _, fs := range t.flows {
		out = append(out, *fs)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Bytes > out[j].Bytes
	})
	if n > 0 && n < len(out) {
		out = out[:n]
	}
	return out
}

func attrStr(attrs map[string]any, key string) string {
	if attrs == nil {
		return ""
	}
	v, ok := attrs[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func attrBool(attrs map[string]any, key string) bool {
	if attrs == nil {
		return false
	}
	v, ok := attrs[key]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(strings.TrimSpace(b), "true")
	default:
		return false
	}
}
