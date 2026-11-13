// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestHeldCreditSettlementTriggers(t *testing.T) {
	for _, trigger := range []string{"verdict", "rejection", "flush", "rejection_then_flush"} {
		t.Run(trigger, func(t *testing.T) {
			h := newIECHarness(t, "enforce")
			table := h.e.sessions
			tok := capture.NewToken(7, 42)
			other := capture.NewToken(8, 42)
			table.mu.Lock()
			ok := table.holdCreditLocked(tok, 13, true) && table.holdCreditLocked(other, 3, true)
			table.mu.Unlock()
			if !ok {
				t.Fatal("admission")
			}
			charge := int64(13) + limits.HeldPacketHeaderAllowanceBytes + limits.HeldTokenMetadataBytes
			otherCharge := int64(3) + limits.HeldPacketHeaderAllowanceBytes + limits.HeldTokenMetadataBytes
			if got := h.e.budget.Status().InUse; got != charge+otherCharge {
				t.Fatalf("charge = %d", got)
			}
			switch trigger {
			case "verdict":
				h.e.hooks.onVerdict(tok, capture.VerdictRepeat, nil)
			case "rejection", "rejection_then_flush":
				h.e.hooks.onCaptureError(fmt.Errorf("wrapped: %w", &capture.ResolutionRejectedError{Token: tok, Err: capture.ErrUnknownToken}))
			case "flush":
				table.onSourceDown(7)
			}
			if trigger == "rejection_then_flush" {
				table.onSourceDown(7)
			}
			h.e.hooks.onVerdict(tok, capture.VerdictRepeat, nil) // duplicate is harmless
			if got := h.e.budget.Status().InUse; got != otherCharge {
				t.Fatalf("wrong token or double refund: %d, want %d", got, otherCharge)
			}
			table.onSourceDown(8)
			if got := h.e.budget.Status().InUse; got != 0 {
				t.Fatalf("leaked %d", got)
			}
		})
	}
}

func TestHeldCreditRefusalAndRetainedSettlement(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	part := iframe(46, 1)
	p, d := h.send(true, part[:3])
	if d.Action != capture.Hold {
		t.Fatal(d)
	}
	_, d = h.send(true, part[3:])
	if d.Action != capture.Repeat || len(d.Resolved) != 1 {
		t.Fatal(d)
	}
	if h.e.budget.Status().ByCategory["held"] != int64(3)+limits.HeldPacketHeaderAllowanceBytes+limits.HeldTokenMetadataBytes {
		t.Fatal("released credit before verdict submission")
	}
	h.e.hooks.onVerdict(p.Token, capture.VerdictRepeat, nil)
	if h.e.budget.Status().ByCategory["held"] != 0 {
		t.Fatal("retained settled packet")
	}
	h.e.Close()
	if h.e.budget.Status().InUse != 0 {
		t.Fatal("shutdown leaked")
	}
}

type rejectingHeldSettler struct{}

func (rejectingHeldSettler) Settle(res ...capture.Resolution) []error {
	errs := make([]error, len(res))
	for i := range errs {
		errs[i] = capture.ErrUnknownToken
	}
	return errs
}

func TestHeldCreditExplicitSettleRejection(t *testing.T) {
	h := newIECHarness(t, "enforce")
	table := h.e.sessions
	tok := capture.NewToken(1, 42)
	table.mu.Lock()
	ok := table.holdCreditLocked(tok, 1, true)
	table.mu.Unlock()
	if !ok {
		t.Fatal("admission")
	}
	table.settler = func() capture.Settler { return rejectingHeldSettler{} }
	table.apply(sessionActions{drops: []capture.Resolution{{Token: tok, Verdict: capture.VerdictDrop}}})
	if h.e.budget.Status().InUse != 0 {
		t.Fatal("explicit settlement rejection leaked")
	}
	h.e.Close()
}

func TestHeldCreditAdmissionBound(t *testing.T) {
	h := newIECHarness(t, "enforce")
	table := h.e.sessions
	table.resources = limits.NewResources(limits.NewBudget(1024), nil)
	table.mu.Lock()
	defer table.mu.Unlock()
	if table.holdCreditLocked(capture.NewToken(1, 1), 1, false) {
		t.Fatal("monitor consumed enforcement headroom")
	}
	if !table.holdCreditLocked(capture.NewToken(1, 2), 1, true) {
		t.Fatal("enforce admission")
	}
	if table.holdCreditLocked(capture.NewToken(1, 3), 1, true) {
		t.Fatal("exceeded budget")
	}
	table.flushHeldCreditsLocked(1)
	if table.resources.Budget.Status().InUse != 0 {
		t.Fatal("leaked failed reservation")
	}
}

func TestHeldCreditRefusalDropsReleasedPrefixBeforePublication(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	p, d := h.send(true, iframe(46, 1)[:3])
	if d.Action != capture.Hold {
		t.Fatal(d)
	}
	table := h.e.sessions
	table.mu.Lock()
	client, _ := addrPort(h.client, h.cport)
	server, _ := addrPort(h.server, iec104Port)
	s, _ := table.lookupLocked(client, server)
	s.dirs[0].framedEnd = 16
	table.resources = limits.NewResources(limits.NewBudget(1), h.e.ledger)
	next := h.pkt(true, capture.TCPFlagACK, h.cSeq, h.sSeq, make([]byte, 16))
	cur := table.current(s, 0, next, h.clock)
	res := table.releaseLocked(s, 0, next, cur, sessionResult{
		inspect: []dpi.Event{{Kind: "request"}},
		acts:    sessionActions{events: []iecTelemetry{{Event: events.Event{Kind: "ics.decision"}}}},
	}, h.clock)
	table.mu.Unlock()
	if !res.stateLimit || res.decision.Action != capture.Drop || len(res.inspect) != 0 {
		t.Fatalf("refused packet published inspection: %+v", res)
	}
	if len(res.decision.Resolved) != 1 || res.decision.Resolved[0].Token != p.Token || res.decision.Resolved[0].Verdict != capture.VerdictDrop {
		t.Fatalf("forwarded a held prefix after refusal: %+v", res.decision)
	}
	for _, ev := range res.acts.events {
		if ev.Kind == "ics.decision" {
			t.Fatal("published an uncommitted decision")
		}
	}
	h.e.hooks.onVerdict(p.Token, capture.VerdictDrop, nil)
	h.e.Close()
}

func TestHeldCreditCaptureErrorWiring(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var delivered error
	var report func(error)
	e.captureConfig.OnError = func(err error) { delivered = err }
	e.captureFactory = func(cfg capture.Config) (CaptureRunner, error) {
		report = cfg.OnError
		return &bindCapture{}, nil
	}
	if err := e.newRun(); err != nil {
		t.Fatal(err)
	}
	tok := capture.NewToken(2, 3)
	e.sessions.mu.Lock()
	ok := e.sessions.holdCreditLocked(tok, 10, true)
	e.sessions.mu.Unlock()
	if !ok {
		t.Fatal("admission")
	}
	rejected := &capture.ResolutionRejectedError{Token: tok, Err: capture.ErrStaleToken}
	report(rejected)
	if delivered != rejected || e.budget.Status().InUse != 0 {
		t.Fatal("capture error was not settled and forwarded")
	}
}
