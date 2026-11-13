// SPDX-License-Identifier: Apache-2.0

package events

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
)

// The old full-ring scan is an oracle for exact context and insertion order.
// Include repeated APDUs, non-IEC context, missing sessions, out-of-order event
// IDs, mixed JSON ID lists, and enough wraps to evict every indexed slot.
func TestIncidentContextIndexMatchesScan(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	s := NewStore(32)
	check := func(ev Event) {
		t.Helper()
		var want []int
		for i := range s.general.events {
			candidate := s.general.at(i)
			if sessionKey(candidate) == sessionKey(ev) && implicated(candidate, ev) {
				want = append(want, i)
			}
		}
		if got := s.incidentContext.matches(s.general, ev); !reflect.DeepEqual(got, want) {
			t.Fatalf("context positions for %+v: got %v want %v", ev, got, want)
		}
		if len(s.incidentContext.heads) > s.capacity || len(s.incidentContext.slots) > s.capacity {
			t.Fatal("index outlived general retention")
		}
	}
	for i := range 1000 {
		session := fmt.Sprint(rng.IntN(4))
		if i%7 == 0 {
			session = ""
		}
		apdu := fmt.Sprint(rng.IntN(4))
		row := iecRow(session, "request", map[string]any{"apdu_id": apdu})
		row.ID = uint64(2000 - i)
		if i%3 == 0 {
			row.Proto = "ids"
		}
		if i%5 == 0 {
			delete(row.Attributes, "apdu_id")
		}
		if i%11 == 0 {
			row.Attributes = nil
		}
		s.Append(row)
		for _, ids := range []any{[]string{"0", "1", apdu}, []any{"2", 42, apdu}} {
			ev := iecRow(session, "ics.verdict", map[string]any{
				"apdu_id": apdu, "trigger_apdu_id": "3", "apdu_ids": ids,
			})
			check(ev)
			s.Append(ev)
			check(ev)
		}
	}
	// Eviction removes every APDU key even when replaced by non-indexed rows.
	for range s.capacity {
		s.Append(Event{})
	}
	if len(s.incidentContext.heads) != 0 {
		t.Fatal("stale APDU keys after eviction")
	}
}
