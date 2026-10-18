// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestRingWrapPreservesGeneralConsumers(t *testing.T) {
	s := NewStore(3)
	for i := 0; i < 11; i++ {
		s.Record(nil, nil, []dpi.Event{{FlowID: "old", Timestamp: time.Unix(int64(i), 0)}})
	}
	s.MarkAborted("gone")
	s.Append(Event{FlowID: "new", Timestamp: time.Unix(11, 0), Attributes: map[string]any{"session_id": "gone"}})
	got := s.List(0)
	for i, e := range got {
		if e.ID != uint64(12-i) {
			t.Fatalf("list = %+v", got)
		}
	}
	match := s.MatchingEvents(func(Event) bool { return true })
	for i, e := range match {
		if e.ID != uint64(10+i) {
			t.Fatalf("matches = %+v", match)
		}
	}
	oldest, newest := s.TimeRange()
	if !oldest.Equal(time.Unix(9, 0)) || !newest.Equal(time.Unix(11, 0)) {
		t.Fatalf("range %v..%v", oldest, newest)
	}
	if f := s.Flows(0); len(f) != 1 || f[0].FlowID != "old" || f[0].EventCount != 2 {
		t.Fatalf("flows = %+v", f)
	}
	for i := 0; i < 4; i++ {
		s.Append(Event{FlowID: "after"})
	}
	s.Flows(0)
	if s.aborted.has("gone") {
		t.Fatal("wrapped ring did not prune stale abort")
	}
}

func TestRingSpillsExactlyEvictedRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	s := NewStoreWithSpill(3, path)
	for i := 0; i < 11; i++ {
		s.Append(Event{})
	}
	s.Close()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	n := 0
	for scan.Scan() {
		n++
		var ev Event
		if err := json.Unmarshal(scan.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.ID != uint64(n) {
			t.Fatalf("spill ID=%d want %d", ev.ID, n)
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 8 || s.SpillCount.Load() != 8 {
		t.Fatalf("spilled %d, count %d", n, s.SpillCount.Load())
	}
}
