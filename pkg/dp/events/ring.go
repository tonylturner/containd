// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

// eventRing stores insertion order without moving retained rows on overflow.
// Callers hold the store mutex. head is the oldest slot once full.
type eventRing struct {
	capacity int
	events   []Event
	head     int
}

func (r *eventRing) push(ev Event) (Event, bool) {
	if len(r.events) < r.capacity {
		r.events = append(r.events, ev)
		return Event{}, false
	}
	old := r.events[r.head]
	r.events[r.head] = ev
	r.head = (r.head + 1) % r.capacity
	return old, true
}

// at indexes chronologically, oldest first, regardless of physical wrap.
func (r eventRing) at(i int) Event {
	return r.events[(r.head+i)%len(r.events)]
}

func (s *Store) appendGeneral(ev Event) {
	s.retainBinding(ev)
	if old, evicted := s.general.push(ev); evicted {
		s.releaseBinding(old)
		s.historyTruncated = true
		s.spillEvent(old)
	}
}
