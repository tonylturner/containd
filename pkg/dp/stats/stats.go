// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package stats

import (
	"net/netip"
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

// Tracker keeps packet/byte accounting separate from DPI event counters.
type Tracker struct {
	mu    sync.RWMutex
	proto map[string]*ProtoStats
	flows map[hostPair]*FlowStats
}

// hostPair deliberately excludes transport ports: top talkers aggregate all
// captured traffic by directional host pair and protocol, not by connection.
// Binary addresses avoid formatting/allocating map keys on every packet.
type hostPair struct {
	src, dst netip.Addr
	protocol string
}

// New creates a new statistics tracker.
func New() *Tracker {
	return &Tracker{
		proto: make(map[string]*ProtoStats),
		flows: make(map[hostPair]*FlowStats),
	}
}

// RecordEvent updates only semantic counters. One decoder event may represent
// one information object, not one transport packet. Event attributes never
// supply transport counters or flow identities.
func (t *Tracker) RecordEvent(ev dpi.Event) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	ps := t.protocolLocked(ev.Proto)
	ps.EventCount++
	if ev.Timestamp.After(ps.LastSeen) {
		ps.LastSeen = ev.Timestamp
	}

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
}

// RecordPacket charges one captured packet and its transport payload bytes to
// exactly one protocol and directional flow, including retransmissions and
// packets that emit no events. Header bytes are not included.
func (t *Tracker) RecordPacket(srcIP, dstIP netip.Addr, protocol string, bytes int, timestamp time.Time) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	ps := t.protocolLocked(protocol)
	ps.PacketCount++
	ps.ByteCount += int64(bytes)
	if timestamp.After(ps.LastSeen) {
		ps.LastSeen = timestamp
	}
	if !srcIP.IsValid() || !dstIP.IsValid() {
		return
	}
	srcIP, dstIP = srcIP.Unmap(), dstIP.Unmap()
	flowKey := hostPair{src: srcIP, dst: dstIP, protocol: ps.Protocol}
	fs, ok := t.flows[flowKey]
	if !ok {
		fs = &FlowStats{SrcIP: srcIP.String(), DstIP: dstIP.String(), Protocol: ps.Protocol}
		t.flows[flowKey] = fs
	}
	fs.Packets++
	fs.Bytes += int64(bytes)
}

// protocolLocked requires t.mu to be held.
func (t *Tracker) protocolLocked(protocol string) *ProtoStats {
	if protocol == "" {
		protocol = "unknown"
	}
	ps, ok := t.proto[protocol]
	if !ok {
		ps = &ProtoStats{Protocol: protocol}
		t.proto[protocol] = ps
	}
	return ps
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
