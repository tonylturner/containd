// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
)

func TestApplyAbortsPartialIECEvenOnNoop(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.e.compiler = enforce.NewCompiler()
	h.e.applier = &recordingApplier{}
	h.e.clearMarks = noPolicyMarks
	h.e.capture = idleCapture{}
	snap := iecSnapshot("enforce")
	// Establish the installed canonical policy before creating a session.
	if err := h.e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	h.handshake()
	held, decision := h.send(true, iframe(46, 1)[:5])
	if decision.Action != capture.Hold {
		t.Fatalf("partial APDU=%+v", decision)
	}
	if err := h.e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	h.e.iec.mu.Lock()
	s, _ := h.e.iec.lookupLocked(goldenClient, goldenServer)
	aborted := s != nil && s.state == iecAborted && len(s.held) == 0
	h.e.iec.mu.Unlock()
	if !aborted || h.e.CurrentRules().AdmissionParity != 0 {
		t.Fatal("no-op commit retained a partial frame or flipped parity")
	}
	h.settler.mu.Lock()
	sends := len(h.settler.calls)
	h.settler.mu.Unlock()
	if sends != 0 {
		t.Fatal("submitted a verdict for an already-flushed token under writer")
	}
	// This harness has no kernel queue: simulate capture's retirement
	// completion, which must finish reset ordering without a source fault.
	h.e.hooks.onVerdict(held.Token, capture.VerdictDrop, capture.ErrTokenFlushed)
	h.waitResets(2)
	if !h.e.IEC104Enforcement().Healthy {
		t.Fatalf("known policy flush became a source fault: %+v", h.e.IEC104Enforcement())
	}
	events := h.eventsOf("ics.verdict")
	if len(events) != 1 || events[0].Attributes["outcome"] != "dropped" {
		t.Fatalf("retirement evidence=%+v", events)
	}
}
