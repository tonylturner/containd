// SPDX-License-Identifier: Apache-2.0

package events

import (
	"slices"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

type incidentAPDU struct{ session, apdu string }

type incidentContextLink struct {
	key        incidentAPDU
	prev, next int
}

// Index only rows still present in the general ring. Intrusive lists use its
// physical slots, so overwriting a row unlinks it in constant time, and memory
// is bounded by general retention, not by session lifetime or packet count.
// Callers hold the store mutex.
type incidentContextIndex struct {
	heads map[incidentAPDU]int
	slots []incidentContextLink
}

func (x *incidentContextIndex) replace(slot int, ev Event) {
	if slot == len(x.slots) {
		x.slots = append(x.slots, incidentContextLink{})
	}
	old := x.slots[slot]
	if old.key.apdu != "" {
		if old.prev >= 0 {
			x.slots[old.prev].next = old.next
		} else if old.next >= 0 {
			x.heads[old.key] = old.next
		} else {
			delete(x.heads, old.key)
		}
		if old.next >= 0 {
			x.slots[old.next].prev = old.prev
		}
	}
	x.slots[slot] = incidentContextLink{}
	apdu, _ := eventfields.String(ev.Attributes, eventfields.KeyAPDUID)
	if apdu == "" {
		return
	}
	key := incidentAPDU{sessionKey(ev), apdu}
	if x.heads == nil {
		x.heads = make(map[incidentAPDU]int)
	}
	next := -1
	if head, ok := x.heads[key]; ok {
		next = head
		x.slots[head].prev = slot
	}
	x.slots[slot] = incidentContextLink{key: key, prev: -1, next: next}
	x.heads[key] = slot
}

// Return chronological ring offsets, matching the former general-ring scan
// exactly, including duplicate references and both live/JSON-decoded ID lists.
// Work depends only on the implicated APDUs, never on unrelated retained rows.
func (x *incidentContextIndex) matches(r eventRing, ev Event) []int {
	var positions []int
	session := sessionKey(ev)
	add := func(apdu string) {
		slot, ok := x.heads[incidentAPDU{session, apdu}]
		if !ok {
			return
		}
		for slot >= 0 {
			positions = append(positions, (slot-r.head+len(r.events))%len(r.events))
			slot = x.slots[slot].next
		}
	}
	for id := range incidentAPDUIDs(ev) {
		add(id)
	}
	slices.Sort(positions)
	return slices.Compact(positions)
}
