// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMatchingEvents(t *testing.T) {
	s := NewStore(100)
	now := time.Now().UTC()

	s.Append(Event{Proto: "ssh", Kind: "version_exchange", Timestamp: now})
	s.Append(Event{Proto: "smb", Kind: "negotiate", Timestamp: now.Add(time.Second)})
	s.Append(Event{Proto: "ssh", Kind: "kex_init", Timestamp: now.Add(2 * time.Second)})
	s.Append(Event{Proto: "dns", Kind: "query", Timestamp: now.Add(3 * time.Second)})

	// Filter for SSH events only.
	results := s.MatchingEvents(func(e Event) bool {
		return e.Proto == "ssh"
	})
	if len(results) != 2 {
		t.Fatalf("expected 2 SSH events, got %d", len(results))
	}
	for _, r := range results {
		if r.Proto != "ssh" {
			t.Errorf("unexpected proto %q in results", r.Proto)
		}
	}
}

func TestMatchingEventsCap(t *testing.T) {
	s := NewStore(2000)

	now := time.Now().UTC()
	for i := 0; i < 1500; i++ {
		s.Append(Event{Proto: "test", Kind: "event", Timestamp: now})
	}

	results := s.MatchingEvents(func(e Event) bool {
		return true
	})
	if len(results) != 1000 {
		t.Fatalf("expected cap at 1000, got %d", len(results))
	}
}

func TestLen(t *testing.T) {
	s := NewStore(100)
	if s.Len() != 0 {
		t.Fatalf("expected 0, got %d", s.Len())
	}

	now := time.Now().UTC()
	s.Append(Event{Proto: "a", Kind: "x", Timestamp: now})
	s.Append(Event{Proto: "b", Kind: "y", Timestamp: now})
	if s.Len() != 2 {
		t.Fatalf("expected 2, got %d", s.Len())
	}
}

func TestTimeRange(t *testing.T) {
	s := NewStore(100)

	oldest, newest := s.TimeRange()
	if !oldest.IsZero() || !newest.IsZero() {
		t.Fatalf("expected zero times for empty store")
	}

	t1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)

	s.Append(Event{Proto: "a", Kind: "x", Timestamp: t1})
	s.Append(Event{Proto: "b", Kind: "y", Timestamp: t2})
	s.Append(Event{Proto: "c", Kind: "z", Timestamp: t3})

	oldest, newest = s.TimeRange()
	if !oldest.Equal(t1) {
		t.Errorf("oldest=%v, want %v", oldest, t1)
	}
	if !newest.Equal(t2) {
		t.Errorf("newest=%v, want %v", newest, t2)
	}
}

func TestRingBufferOverflow(t *testing.T) {
	capacity := 5
	s := NewStore(capacity)

	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		s.Append(Event{
			Proto:     "test",
			Kind:      "event",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}

	if s.Len() != capacity {
		t.Fatalf("expected len=%d after overflow, got %d", capacity, s.Len())
	}

	// The oldest events should have been evicted. List returns newest-first.
	events := s.List(capacity)
	if len(events) != capacity {
		t.Fatalf("expected %d events from List, got %d", capacity, len(events))
	}

	// Newest event should be the last one inserted (i=9).
	newestTS := now.Add(9 * time.Second)
	if !events[0].Timestamp.Equal(newestTS) {
		t.Errorf("newest event timestamp=%v, want %v", events[0].Timestamp, newestTS)
	}

	// Oldest retained should be i=5.
	oldestTS := now.Add(5 * time.Second)
	if !events[capacity-1].Timestamp.Equal(oldestTS) {
		t.Errorf("oldest retained timestamp=%v, want %v", events[capacity-1].Timestamp, oldestTS)
	}
}

func TestSpillCount(t *testing.T) {
	dir := t.TempDir()
	spillFile := filepath.Join(dir, "spill.jsonl")

	capacity := 5
	s := NewStoreWithSpill(capacity, spillFile)

	now := time.Now().UTC()
	// Add more events than capacity to trigger spill.
	for i := 0; i < 10; i++ {
		s.Append(Event{
			Proto:     "test",
			Kind:      "event",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}

	// Close flushes the spill writer.
	s.Close()

	// SpillCount should reflect evicted events.
	sc := s.SpillCount.Load()
	if sc == 0 {
		t.Fatalf("expected SpillCount > 0, got %d", sc)
	}

	// Verify the spill file was written.
	info, err := os.Stat(spillFile)
	if err != nil {
		t.Fatalf("spill file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("spill file is empty")
	}
}

func TestCloseWithoutSpill(t *testing.T) {
	s := NewStore(10)
	// Close should be safe even without spill configured.
	s.Close()
}

func TestNilStore(t *testing.T) {
	var s *Store
	if s.Len() != 0 {
		t.Fatalf("nil store Len() should be 0")
	}
	oldest, newest := s.TimeRange()
	if !oldest.IsZero() || !newest.IsZero() {
		t.Fatalf("nil store TimeRange should return zero times")
	}
	results := s.MatchingEvents(func(e Event) bool { return true })
	if results != nil {
		t.Fatalf("nil store MatchingEvents should return nil")
	}
}
