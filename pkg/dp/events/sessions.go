// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

const (
	protoIEC104  = "iec104"
	keySessionID = "session_id"
	keyDirection = "direction"
	// maxAbortedSessions bounds the aborted-incarnation set.
	maxAbortedSessions = 4096
)

// flowGroup returns the Flows group key of an event and, for an IEC104
// incarnation, its session ID. Any event that carries a session_id groups
// with that incarnation, including derived evidence (signature and anomaly
// alerts) and the engine's decision and outcome events.
func flowGroup(ev Event) (key, sessionID string) {
	if id, ok := ev.Attributes[keySessionID].(string); ok && id != "" {
		return "session/" + id, id
	}
	return ev.FlowID, ""
}

// isClientSide reports an event whose tuple is the session tuple (client →
// server): client requests and the engine's own session events.
func isClientSide(ev Event) bool {
	dir, _ := ev.Attributes[keyDirection].(string)
	return dir == "request" || (ev.Proto == protoIEC104 && dir == "" && ev.SrcIP != "")
}

// abortedSet is a bounded set of aborted incarnations. An entry lives as
// long as a retained event could recreate its group, and at least until
// the ring next passes it: a session's late outcome events (resets) arrive
// after the abort.
type abortedSet struct {
	ids   map[string]uint64 // session ID -> next event ID when marked
	order []string
}

func (a *abortedSet) has(id string) bool {
	_, ok := a.ids[id]
	return ok
}

func (a *abortedSet) add(id string, ring eventRing) {
	if a.ids == nil {
		a.ids = make(map[string]uint64)
	}
	if _, ok := a.ids[id]; ok {
		return
	}
	var next uint64
	if n := len(ring.events); n > 0 {
		next = ring.at(n-1).ID + 1
	}
	a.ids[id] = next
	a.order = append(a.order, id)
	for len(a.order) > maxAbortedSessions {
		delete(a.ids, a.order[0])
		a.order = a.order[1:]
	}
}

// prune forgets incarnations that no retained event names, once the ring
// holds only events newer than the mark (so nothing older can return).
func (a *abortedSet) prune(ring eventRing) {
	if len(a.ids) == 0 || len(ring.events) == 0 {
		return
	}
	live := map[string]bool{}
	for _, ev := range ring.events {
		if _, id := flowGroup(ev); id != "" {
			live[id] = true
		}
	}
	oldest := ring.at(0).ID
	kept := a.order[:0]
	for _, id := range a.order {
		if !live[id] && oldest > a.ids[id] {
			delete(a.ids, id)
			continue
		}
		kept = append(kept, id)
	}
	a.order = kept
}
