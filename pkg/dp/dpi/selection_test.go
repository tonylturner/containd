// SPDX-License-Identifier: Apache-2.0

package dpi

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

func assertSelectionsEmpty(t *testing.T, manager *Manager) {
	t.Helper()
	if len(manager.selected) != 0 || len(manager.flowStreams) != 0 || len(manager.streamFlows) != 0 {
		t.Fatalf("retained selections: selected=%v flowStreams=%v streamFlows=%v",
			manager.selected, manager.flowStreams, manager.streamFlows)
	}
}

func TestSelectionFlowEnd(t *testing.T) {
	for _, session := range []bool{false, true} {
		for _, explicitEnd := range []bool{false, true} {
			if explicitEnd && !session {
				continue
			}
			name := "flow"
			if session {
				name = "session"
			}
			if explicitEnd {
				name += "/EndStream"
			} else {
				name += "/flow-expiry-only"
			}
			t.Run(name, func(t *testing.T) {
				decoder := &statefulStreamDecoder{}
				manager := NewManager(decoder)
				state := streamEndState(1, false)
				state.IdleTimeout = time.Second
				for _, dir := range []StreamDir{ClientToServer, ServerToClient} {
					pkt := legacyStreamPacket(dir)
					if session {
						pkt = sessionSeg("selection-expiry", dir, 0, 0x42)
					}
					if res := manager.Inspect(state, pkt); res.Err != nil {
						t.Fatal(res.Err)
					}
				}
				if len(manager.selected) == 0 {
					t.Fatal("test did not commit a decoder")
				}
				if explicitEnd && session {
					manager.EndStream("selection-expiry")
					assertSelectionsEmpty(t, manager)
				}
				// This is the engine sweep's lifecycle callback; no EndStream
				// occurs on the flow-expiry-only session path.
				if !state.Expired(state.LastSeen.Add(2 * time.Second)) {
					t.Fatal("test flow did not expire")
				}
				if _, err := manager.OnFlowEnd(state); err != nil {
					t.Fatal(err)
				}
				assertSelectionsEmpty(t, manager)
				if len(manager.reassembler.streams) != 0 || len(manager.streamEnds) != 0 || len(manager.eventTimes) != 0 {
					t.Fatal("flow end retained stream state")
				}
			})
		}
	}
}

func TestSelectionSessionWithoutStreamEnder(t *testing.T) {
	// Ownership must not depend on StreamEnder: many decoders are stateless,
	// and a selection can commit before the first payload has been parsed.
	manager := NewManager(&mockStreamDecoder{})
	state := streamEndState(2, false)
	manager.Inspect(state, sessionSeg("unparsed", ClientToServer, 0))
	if len(manager.selected) != 1 {
		t.Fatal("unparsed stream did not commit")
	}
	manager.DiscardFlow(state)
	assertSelectionsEmpty(t, manager)
}

func TestSelectionSharedSessionSurvivesOneWireLeg(t *testing.T) {
	decoder := &statefulStreamDecoder{}
	manager := NewManager(decoder)
	first, second := streamEndState(3, false), streamEndState(4, false)
	pkt := sessionSeg("shared", ClientToServer, 0, 0x42)
	manager.Inspect(first, pkt)
	manager.Inspect(second, pkt)
	if _, err := manager.OnFlowEnd(first); err != nil {
		t.Fatal(err)
	}
	if len(manager.selected) != 1 {
		t.Fatal("ending one wire leg retired a live session selection")
	}
	if _, ended := decoder.calls(); len(ended) != 0 {
		t.Fatal("ending one wire leg ended a live session decoder")
	}
	if _, err := manager.OnFlowEnd(second); err != nil {
		t.Fatal(err)
	}
	assertSelectionsEmpty(t, manager)
	assertStreamEndCalls(t, decoder, streamEndCall{session: "shared", dir: ClientToServer})
}

func TestSelectionExplicitEndReleasesAllOwners(t *testing.T) {
	manager := NewManager(&statefulStreamDecoder{})
	for _, state := range []*flow.State{streamEndState(5, false), streamEndState(6, false)} {
		manager.Inspect(state, sessionSeg("shared", ClientToServer, 0, 0x42))
	}
	manager.EndStream("shared")
	assertSelectionsEmpty(t, manager)
}
