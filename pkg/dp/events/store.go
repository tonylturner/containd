// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
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

const (
	defaultSpillChanSize = 1024
	spillMaxFileSize     = 50 * 1024 * 1024 // 50 MB
	spillMaxFiles        = 5
	spillFlushInterval   = 5 * time.Second
)

// Store holds a bounded ring buffer of recent events with optional
// spill-to-disk for overflow events.
type Store struct {
	capacity int
	idBase   uint64
	nextID   atomic.Uint64

	mu     sync.Mutex
	events []Event

	// Spill-to-disk support.
	spillPath string
	spillCh   chan Event
	spillDone chan struct{}

	SpillCount atomic.Uint64
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

// NewStoreWithSpill creates a Store with spill-to-disk enabled.
// Events that overflow the ring buffer are written to spillPath as JSONL.
func NewStoreWithSpill(capacity int, spillPath string) *Store {
	s := NewStore(capacity)
	if spillPath != "" {
		s.spillPath = spillPath
		s.spillCh = make(chan Event, defaultSpillChanSize)
		s.spillDone = make(chan struct{})
		go s.spillWriter()
	}
	return s
}

// spillWriter runs in a goroutine, draining spillCh and appending events
// to the spill file as JSONL.  It uses buffered I/O and periodic flushing.
func (s *Store) spillWriter() {
	defer close(s.spillDone)

	f, err := os.OpenFile(s.spillPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 32*1024)
	ticker := time.NewTicker(spillFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-s.spillCh:
			if !ok {
				// Channel closed — flush and return.
				_ = w.Flush()
				return
			}
			data, jerr := json.Marshal(ev)
			if jerr != nil {
				continue
			}
			_, _ = w.Write(data)
			_ = w.WriteByte('\n')
			s.SpillCount.Add(1)

			// Check file size for rotation.
			if info, serr := f.Stat(); serr == nil && info.Size()+int64(w.Buffered()) >= spillMaxFileSize {
				_ = w.Flush()
				f.Close()
				s.rotateSpillFiles()
				f, err = os.OpenFile(s.spillPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
				if err != nil {
					return
				}
				w.Reset(f)
			}
		case <-ticker.C:
			_ = w.Flush()
		}
	}
}

// rotateSpillFiles renames spillPath -> .1, .1 -> .2, etc., keeping at
// most spillMaxFiles rotated files.
func (s *Store) rotateSpillFiles() {
	// Remove the oldest file if it exists.
	oldest := fmt.Sprintf("%s.%d", s.spillPath, spillMaxFiles)
	_ = os.Remove(oldest)

	// Shift .N-1 -> .N
	for i := spillMaxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", s.spillPath, i)
		dst := fmt.Sprintf("%s.%d", s.spillPath, i+1)
		_ = os.Rename(src, dst)
	}

	// Rename current file to .1
	_ = os.Rename(s.spillPath, fmt.Sprintf("%s.1", s.spillPath))
}

// Close flushes and closes the spill writer.  Safe to call even if spill
// is not configured.
func (s *Store) Close() {
	if s == nil || s.spillCh == nil {
		return
	}
	close(s.spillCh)
	<-s.spillDone
}

// spillEvent sends an event to the spill writer without blocking the
// caller.  If the channel is full, the event is dropped.
func (s *Store) spillEvent(ev Event) {
	if s.spillCh == nil {
		return
	}
	select {
	case s.spillCh <- ev:
	default:
		// Channel full — drop to avoid blocking the hot path.
	}
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
			// Drop oldest — shift in place to avoid re-allocation.
			shift := len(s.events) - s.capacity
			// Spill the evicted events before discarding.
			if s.spillCh != nil {
				for i := 0; i < shift; i++ {
					s.spillEvent(s.events[i])
				}
			}
			copy(s.events, s.events[shift:])
			s.events = s.events[:s.capacity]
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
		if s.spillCh != nil {
			for i := 0; i < shift; i++ {
				s.spillEvent(s.events[i])
			}
		}
		copy(s.events, s.events[shift:])
		s.events = s.events[:s.capacity]
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

// MatchingEvents returns events from the store that match the given predicate.
// Results are capped at 1000 to bound response size. Used for rule impact preview.
func (s *Store) MatchingEvents(predicate func(Event) bool) []Event {
	if s == nil {
		return nil
	}
	const maxResults = 1000
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for i := range s.events {
		if predicate(s.events[i]) {
			out = append(out, s.events[i])
			if len(out) >= maxResults {
				break
			}
		}
	}
	return out
}

// Len returns the number of events currently in the store.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// TimeRange returns the timestamps of the oldest and newest events in the store.
// If the store is empty, both times are zero.
func (s *Store) TimeRange() (oldest, newest time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		return
	}
	oldest = s.events[0].Timestamp
	newest = s.events[0].Timestamp
	for i := 1; i < len(s.events); i++ {
		if s.events[i].Timestamp.Before(oldest) {
			oldest = s.events[i].Timestamp
		}
		if s.events[i].Timestamp.After(newest) {
			newest = s.events[i].Timestamp
		}
	}
	return
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
