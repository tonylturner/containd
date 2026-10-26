// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/events"
)

func TestReconfigureKeepsSharedEventStore(t *testing.T) {
	store := events.NewStore(4096)
	build := func() *Engine {
		t.Helper()
		e, err := New(Config{Events: store})
		if err != nil {
			t.Fatal(err)
		}
		if e.Events() != store {
			t.Fatal("New did not use the supplied store")
		}
		return e
	}
	e := build()
	before := store.Append(events.Event{Kind: "before"})
	e.Reconfigure(build())
	after := e.Events().Append(events.Event{Kind: "after"})
	list := e.Events().List(0)
	if len(list) != 2 || list[1].ID != before.ID || list[0].ID != after.ID || after.ID <= before.ID {
		t.Fatalf("event history/IDs changed across rebuild: %+v", list)
	}

	// Exercise all store-bound IEC callbacks on the replacement table.
	sessionID := nextLiveSessionID()
	e.iec.emit([]events.Event{{Proto: "iec104", Kind: "response",
		Attributes: map[string]any{"session_id": sessionID}}})
	if got := store.Flows(0); len(got) != 2 { // one generic group + the IEC session
		t.Fatalf("IEC emit did not reach the shared store: %+v", got)
	}
	e.iec.markAbort(sessionID)
	if got := store.Flows(0); len(got) != 1 {
		t.Fatalf("IEC markAbort did not reach the shared store: %+v", got)
	}
	e.iec.health.setActive(true) // no inline injector: emit enforce_unhealthy
	last := store.List(1)[0]
	if last.Kind != "ics.session" || last.Attributes["outcome"] != outcomeEnforceUnhealthy {
		t.Fatalf("IEC health did not reach the shared store: %+v", last)
	}
}

func TestNewWithoutEventsAllocatesPrivateStore(t *testing.T) {
	a, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Events() == nil || b.Events() == nil || a.Events() == b.Events() {
		t.Fatal("standalone engines must have independent default stores")
	}
}
