// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Event is a normalized DPI/IDS/Firewall event for telemetry.
type Event struct {
	ID         uint64         `json:"id"`
	FlowID     string         `json:"flowId"`
	Proto      string         `json:"proto"`
	Kind       string         `json:"kind"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
	SrcIP      string         `json:"srcIp,omitempty"`
	DstIP      string         `json:"dstIp,omitempty"`
	SrcPort    uint16         `json:"srcPort,omitempty"`
	DstPort    uint16         `json:"dstPort,omitempty"`
	Transport  string         `json:"transport,omitempty"` // tcp/udp
	Hash       string         `json:"hash,omitempty"`      // optional content hash for AV events
}

// FlowSummary is a coarse flow rollup derived from events.
type FlowSummary struct {
	FlowID      string    `json:"flowId"`
	FirstSeen   time.Time `json:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen"`
	SrcIP       string    `json:"srcIp,omitempty"`
	DstIP       string    `json:"dstIp,omitempty"`
	SrcPort     uint16    `json:"srcPort,omitempty"`
	DstPort     uint16    `json:"dstPort,omitempty"`
	Transport   string    `json:"transport,omitempty"`
	Application string    `json:"application,omitempty"`
	EventCount  uint64    `json:"eventCount"`
	AvDetected  bool      `json:"avDetected,omitempty"`
	AvBlocked   bool      `json:"avBlocked,omitempty"`
}

// Store holds a bounded ring buffer of recent events.
type Store struct {
	capacity int
	idBase   uint64
	nextID   atomic.Uint64

	mu     sync.Mutex
	events []Event
}

func NewStore(capacity int) *Store {
	return NewStoreWithIDBase(capacity, 0)
}

func NewStoreWithIDBase(capacity int, idBase uint64) *Store {
	if capacity <= 0 {
		capacity = 4096
	}
	return &Store{capacity: capacity, idBase: idBase}
}

// Record converts DPI events into normalized events and appends them.
func (s *Store) Record(state *flow.State, pkt *dpi.ParsedPacket, in []dpi.Event) {
	if s == nil || len(in) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ev := range in {
		id := s.idBase + s.nextID.Add(1)
		out := Event{
			ID:         id,
			FlowID:     ev.FlowID,
			Proto:      ev.Proto,
			Kind:       ev.Kind,
			Attributes: ev.Attributes,
			Timestamp:  ev.Timestamp,
		}
		if state != nil {
			out.SrcIP = state.Key.SrcIP.String()
			out.DstIP = state.Key.DstIP.String()
			out.SrcPort = state.Key.SrcPort
			out.DstPort = state.Key.DstPort
		}
		if pkt != nil {
			out.Transport = pkt.Proto
		}
		s.events = append(s.events, out)
		if len(s.events) > s.capacity {
			// Drop oldest.
			shift := len(s.events) - s.capacity
			s.events = append([]Event{}, s.events[shift:]...)
		}
	}
}

// Append adds an already-normalized event (e.g. system/service events) to the buffer.
// If e.ID is zero, a new unique ID is assigned from the store's counter.
func (s *Store) Append(e Event) Event {
	if s == nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.ID == 0 {
		e.ID = s.idBase + s.nextID.Add(1)
	}
	s.events = append(s.events, e)
	if len(s.events) > s.capacity {
		shift := len(s.events) - s.capacity
		s.events = append([]Event{}, s.events[shift:]...)
	}
	return e
}

// List returns recent events newest-first, up to limit.
func (s *Store) List(limit int) []Event {
	if s == nil {
		return nil
	}
	if limit <= 0 || limit > s.capacity {
		limit = s.capacity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.events)
	if n == 0 {
		return nil
	}
	if limit > n {
		limit = n
	}
	out := make([]Event, 0, limit)
	for i := n - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.events[i])
	}
	return out
}

// Flows derives flow summaries from the stored events.
func (s *Store) Flows(limit int) []FlowSummary {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		return nil
	}
	byFlow := map[string]*FlowSummary{}
	for _, ev := range s.events {
		f, ok := byFlow[ev.FlowID]
		if !ok {
			f = &FlowSummary{
				FlowID:      ev.FlowID,
				FirstSeen:   ev.Timestamp,
				LastSeen:    ev.Timestamp,
				SrcIP:       ev.SrcIP,
				DstIP:       ev.DstIP,
				SrcPort:     ev.SrcPort,
				DstPort:     ev.DstPort,
				Transport:   ev.Transport,
				Application: ev.Proto,
			}
			byFlow[ev.FlowID] = f
		}
		if ev.Timestamp.Before(f.FirstSeen) {
			f.FirstSeen = ev.Timestamp
		}
		if ev.Timestamp.After(f.LastSeen) {
			f.LastSeen = ev.Timestamp
		}
		f.EventCount++
		if f.Application == "" {
			f.Application = ev.Proto
		}
		if strings.EqualFold(ev.Kind, "service.av.detected") {
			f.AvDetected = true
		}
		if strings.EqualFold(ev.Kind, "service.av.block_flow") {
			f.AvBlocked = true
		}
	}
	out := make([]FlowSummary, 0, len(byFlow))
	for _, f := range byFlow {
		out = append(out, *f)
	}
	// no sorting needed for v1; caller can sort.
	if limit <= 0 || limit > len(out) {
		return out
	}
	return out[:limit]
}
