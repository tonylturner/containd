// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

import (
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestTelemetryDenySurvivesGeneralWrap(t *testing.T) {
	for _, path := range []string{"append-nflog", "record"} {
		t.Run(path, func(t *testing.T) {
			s := NewStore(4)
			original := Event{Kind: "firewall.rule.hit", FlowID: "denied", Timestamp: time.Unix(1, 123), SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 1234, DstPort: 2404, Transport: "tcp", Attributes: map[string]any{"action": "DENY", "via": "nflog"}}
			if path == "record" {
				s.Record(stateOf(original.SrcIP, original.DstIP, original.SrcPort, original.DstPort), &dpi.ParsedPacket{Proto: "tcp"}, []dpi.Event{{Kind: original.Kind, FlowID: original.FlowID, Timestamp: original.Timestamp, Attributes: original.Attributes}})
				original.ID = s.List(0)[0].ID
			} else {
				original = s.Append(original)
			}
			for i := 0; i < 20; i++ {
				s.Append(Event{FlowID: "current", Timestamp: time.Unix(int64(100+i), 0)})
			}
			got := s.ListTelemetry(1)
			if len(got) != 1 || !reflect.DeepEqual(got[0], original) {
				t.Fatalf("protected event changed/lost: %+v want %+v", got, original)
			}
			if len(s.ListTelemetry(5)) != 5 || s.Len() != 4 {
				t.Fatal("bank must add to—not expand—the general ring")
			}
			if f := s.Flows(0); len(f) != 1 || f[0].FlowID != "current" {
				t.Fatalf("bank leaked to flows: %+v", f)
			}
			if m := s.MatchingEvents(func(e Event) bool { return e.ID == original.ID }); len(m) != 0 {
				t.Fatalf("bank leaked to matches: %+v", m)
			}
		})
	}
}

func TestTelemetryBankEvictedOnlyByDenies(t *testing.T) {
	s := NewStore(2)
	first := s.Append(Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"action": "DENY"}})
	for i := 0; i < denyCapacity*2; i++ {
		s.Append(Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"action": "ALLOW"}})
	}
	if len(s.denies.events) != 1 || s.ListTelemetry(1)[0].ID != first.ID {
		t.Fatal("ALLOW traffic evicted bank")
	}
	// Wrong kind and wrong action type are not DENYs.
	s.Append(Event{Kind: "ics.decision", Attributes: map[string]any{"action": "DENY"}})
	s.Append(Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"action": []string{"DENY"}}})
	for i := 1; i < denyCapacity; i++ {
		s.Append(Event{Kind: "firewall.rule.hit", Timestamp: time.Unix(int64(i), 0), Attributes: map[string]any{"action": "DENY"}})
	}
	if len(s.denies.events) != denyCapacity || len(s.ListTelemetry(denyCapacity)) != denyCapacity {
		t.Fatal("bank boundary not retained")
	}
	found := false
	for _, e := range s.ListTelemetry(0) {
		found = found || e.ID == first.ID
	}
	if !found {
		t.Fatal("first row evicted before DENY overflow")
	}
	s.Append(Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"action": "DENY"}})
	for _, e := range s.ListTelemetry(0) {
		if e.ID == first.ID {
			t.Fatal("first row survived DENY overflow")
		}
	}
	if len(s.denies.events) != denyCapacity {
		t.Fatal("bank exceeds capacity")
	}
}

func TestSelectTelemetryLimitsDedupeAndOrder(t *testing.T) {
	old := Event{ID: 1, Kind: "firewall.rule.hit", Timestamp: time.Unix(1, 0), Attributes: map[string]any{"action": "DENY"}}
	recent := old
	recent.ID = 2
	recent.Timestamp = time.Unix(2, 0)
	input := []Event{{ID: 3, Timestamp: time.Unix(3, 0)}, old, recent, old, {ID: 4, Timestamp: time.Unix(4, 0)}}
	for _, tc := range []struct {
		limit int
		ids   []uint64
	}{{1, []uint64{2}}, {2, []uint64{2, 1}}, {3, []uint64{4, 2, 1}}, {4, []uint64{4, 3, 2, 1}}, {5, []uint64{4, 3, 2, 1}}, {0, []uint64{4, 3, 2, 1}}} {
		got := SelectTelemetry(input, tc.limit)
		ids := []uint64{}
		for _, e := range got {
			ids = append(ids, e.ID)
		}
		if !reflect.DeepEqual(ids, tc.ids) {
			t.Fatalf("limit %d: %v want %v", tc.limit, ids, tc.ids)
		}
	}
	// Error must remain visible even with future-dated DENYs and limit one.
	errorRow := Event{Kind: "system.engine.telemetry_error", Timestamp: time.Unix(0, 0)}
	if got := SelectTelemetry(append(input, errorRow), 1); len(got) != 1 || got[0].Kind != errorRow.Kind {
		t.Fatalf("lost error: %+v", got)
	}
	if input[0].ID != 3 {
		t.Fatal("selection mutated input")
	}
	var nilStore *Store
	if nilStore.ListTelemetry(1) != nil {
		t.Fatal("nil store")
	}
}
