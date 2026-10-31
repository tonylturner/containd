// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

type kernelVerdict struct {
	id uint32
	v  Verdict
}

type completionRecord struct {
	tok    Token
	v      Verdict
	err    error
	source *SourceEvent
}

// inlineFixture is one inline generation with a fake kernel and recorded
// completions.
type inlineFixture struct {
	t       *testing.T
	settler *settler
	comp    *completer
	gen     *generation

	mu        sync.Mutex
	kernel    []kernelVerdict
	submitErr map[uint32]error
	done      []completionRecord
	errs      []error
}

func newInlineFixture(t *testing.T) *inlineFixture {
	t.Helper()
	fx := &inlineFixture{t: t, settler: &settler{inline: true}, submitErr: map[uint32]error{}}
	fx.comp = newCompleter(func(tok Token, v Verdict, err error) {
		fx.mu.Lock()
		fx.done = append(fx.done, completionRecord{tok: tok, v: v, err: err})
		fx.mu.Unlock()
	}, func(ev SourceEvent) {
		fx.mu.Lock()
		fx.done = append(fx.done, completionRecord{source: &ev})
		fx.mu.Unlock()
	})
	t.Cleanup(fx.comp.close)
	fx.gen = fx.newGeneration()
	return fx
}

func (fx *inlineFixture) newGeneration() *generation {
	g := newGeneration(fx.submit, fx.comp, func(err error) {
		fx.mu.Lock()
		fx.errs = append(fx.errs, err)
		fx.mu.Unlock()
	})
	fx.settler.publish(g)
	return g
}

func (fx *inlineFixture) submit(id uint32, v Verdict, _ uint32) error {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	fx.kernel = append(fx.kernel, kernelVerdict{id, v})
	return fx.submitErr[id]
}

func (fx *inlineFixture) deliver(id uint32, h Handler) Token {
	fx.gen.deliver(id, Packet{}, h)
	return Token{gen: fx.gen.id, id: id}
}

func (fx *inlineFixture) hold(id uint32) Token {
	return fx.deliver(id, func(Packet) Decision { return Decision{Action: Hold} })
}

func (fx *inlineFixture) completions() []completionRecord {
	fx.comp.flush()
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return append([]completionRecord(nil), fx.done...)
}

func (fx *inlineFixture) kernelVerdicts() []kernelVerdict {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return append([]kernelVerdict(nil), fx.kernel...)
}

func (fx *inlineFixture) reported() []error {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return append([]error(nil), fx.errs...)
}

func verdictOf(tok Token, v Verdict) completionRecord {
	return completionRecord{tok: tok, v: v}
}

func TestInlineImmediateAcceptHasNoCompletion(t *testing.T) {
	fx := newInlineFixture(t)
	var seen Token
	tok := fx.deliver(7, func(p Packet) Decision { seen = p.Token; return Decision{Action: Accept} })
	if seen != tok || !seen.Inline() {
		t.Fatalf("handler saw token %v, want %v", seen, tok)
	}
	if got := fx.kernelVerdicts(); !reflect.DeepEqual(got, []kernelVerdict{{7, VerdictAccept}}) {
		t.Fatalf("kernel = %+v", got)
	}
	if got := fx.completions(); len(got) != 0 {
		t.Fatalf("completions = %+v, want none for a never-held accept", got)
	}
	if errs := fx.settler.Settle(Resolution{Token: tok, Verdict: VerdictDrop}); !errors.Is(errs[0], ErrUnknownToken) {
		t.Fatalf("Settle after submission = %v, want ErrUnknownToken", errs[0])
	}
}

func TestInlineImmediateAcceptNotificationExactlyOnce(t *testing.T) {
	fx := newInlineFixture(t)
	tok := fx.deliver(7, func(Packet) Decision { return Decision{Action: Accept, Notify: true} })
	fx.gen.close(nil)
	got := fx.completions()
	if len(got) != 2 || got[0] != verdictOf(tok, VerdictAccept) || got[1].source == nil {
		t.Fatalf("expected one successful Accept followed by source down: %+v", got)
	}
}

func TestInlineDropAndHoldSettleExactlyOnce(t *testing.T) {
	fx := newInlineFixture(t)
	dropped := fx.deliver(1, func(Packet) Decision { return Decision{Action: Drop} })
	held := fx.hold(2)
	if got := fx.kernelVerdicts(); !reflect.DeepEqual(got, []kernelVerdict{{1, VerdictDrop}}) {
		t.Fatalf("kernel before settle = %+v; a held packet must not get a verdict", got)
	}
	if errs := fx.settler.Settle(Resolution{Token: held, Verdict: VerdictAccept}); errs[0] != nil {
		t.Fatalf("Settle = %v", errs[0])
	}
	for _, again := range []Verdict{VerdictAccept, VerdictDrop} {
		if errs := fx.settler.Settle(Resolution{Token: held, Verdict: again}); !errors.Is(errs[0], ErrUnknownToken) {
			t.Fatalf("second Settle = %v, want ErrUnknownToken", errs[0])
		}
	}
	want := []completionRecord{verdictOf(dropped, VerdictDrop), verdictOf(held, VerdictAccept)}
	if got := fx.completions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("completions = %+v, want %+v", got, want)
	}
	if got := fx.kernelVerdicts(); !reflect.DeepEqual(got, []kernelVerdict{{1, VerdictDrop}, {2, VerdictAccept}}) {
		t.Fatalf("kernel = %+v", got)
	}
}

// One decision batch submits every Drop before any Accept; the current
// packet goes first within its class.
func TestInlineDecisionBatchDropsBeforeAccepts(t *testing.T) {
	fx := newInlineFixture(t)
	t1, t2, t3 := fx.hold(1), fx.hold(2), fx.hold(3)
	cur := fx.deliver(4, func(Packet) Decision {
		return Decision{Action: Accept, Resolved: []Resolution{
			{Token: t1, Verdict: VerdictAccept},
			{Token: t2, Verdict: VerdictDrop},
			{Token: t3, Verdict: VerdictAccept},
			{Token: t3, Verdict: VerdictDrop}, // Drop wins over an Accept not yet submitted
		}}
	})
	wantKernel := []kernelVerdict{{2, VerdictDrop}, {3, VerdictDrop}, {4, VerdictAccept}, {1, VerdictAccept}}
	if got := fx.kernelVerdicts(); !reflect.DeepEqual(got, wantKernel) {
		t.Fatalf("kernel = %+v, want %+v", got, wantKernel)
	}
	want := []completionRecord{verdictOf(t2, VerdictDrop), verdictOf(t3, VerdictDrop), verdictOf(t1, VerdictAccept)}
	if got := fx.completions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("completions = %+v, want %+v (current accept %v reports nothing)", got, want, cur)
	}
}

func TestInlineDecisionCurrentDropFirst(t *testing.T) {
	fx := newInlineFixture(t)
	t1, t2 := fx.hold(1), fx.hold(2)
	cur := fx.deliver(3, func(Packet) Decision {
		return Decision{Action: Drop, Resolved: []Resolution{{Token: t1, Verdict: VerdictAccept}, {Token: t2, Verdict: VerdictDrop}}}
	})
	wantKernel := []kernelVerdict{{3, VerdictDrop}, {2, VerdictDrop}, {1, VerdictAccept}}
	if got := fx.kernelVerdicts(); !reflect.DeepEqual(got, wantKernel) {
		t.Fatalf("kernel = %+v, want %+v", got, wantKernel)
	}
	want := []completionRecord{verdictOf(cur, VerdictDrop), verdictOf(t2, VerdictDrop), verdictOf(t1, VerdictAccept)}
	if got := fx.completions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("completions = %+v, want %+v", got, want)
	}
}

// A Settle that names the running callback's own token is staged and
// applied when the callback returns; Drop wins.
func TestInlineSettleDuringCallbackIsStaged(t *testing.T) {
	cases := []struct {
		name   string
		staged []Verdict
		action Disposition
		want   Verdict
	}{
		{"hold+accept", []Verdict{VerdictAccept}, Hold, VerdictAccept},
		{"hold+drop", []Verdict{VerdictDrop}, Hold, VerdictDrop},
		{"accept+drop", []Verdict{VerdictDrop}, Accept, VerdictDrop},
		{"drop+accept", []Verdict{VerdictAccept}, Drop, VerdictDrop},
		{"accept+accept", []Verdict{VerdictAccept}, Accept, VerdictAccept},
		{"hold+drop then accept", []Verdict{VerdictDrop, VerdictAccept}, Hold, VerdictDrop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newInlineFixture(t)
			tok := fx.deliver(9, func(p Packet) Decision {
				for _, v := range tc.staged {
					if errs := fx.settler.Settle(Resolution{Token: p.Token, Verdict: v}); errs[0] != nil {
						t.Errorf("staged Settle = %v, want nil", errs[0])
					}
				}
				if got := fx.kernelVerdicts(); len(got) != 0 {
					t.Errorf("staged request submitted during the callback: %+v", got)
				}
				return Decision{Action: tc.action}
			})
			if got := fx.kernelVerdicts(); !reflect.DeepEqual(got, []kernelVerdict{{9, tc.want}}) {
				t.Fatalf("kernel = %+v, want one %v", got, tc.want)
			}
			if got := fx.completions(); !reflect.DeepEqual(got, []completionRecord{verdictOf(tok, tc.want)}) {
				t.Fatalf("completions = %+v", got)
			}
		})
	}
}

// Settle from inside a handler for an earlier token submits at once, and
// OnVerdict never runs on the caller's stack.
func TestInlineSettleInsideHandlerNeverCallsOnVerdictInline(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var got []Token
	comp := newCompleter(func(tok Token, _ Verdict, _ error) {
		<-release
		mu.Lock()
		got = append(got, tok)
		mu.Unlock()
	}, nil)
	defer comp.close()
	st := &settler{inline: true}
	var kernel []kernelVerdict
	g := newGeneration(func(id uint32, v Verdict, _ uint32) error { kernel = append(kernel, kernelVerdict{id, v}); return nil }, comp, nil)
	st.publish(g)

	g.deliver(1, Packet{}, func(Packet) Decision { return Decision{Action: Hold} })
	held := Token{gen: g.id, id: 1}
	returned := make(chan []error, 1)
	g.deliver(2, Packet{}, func(Packet) Decision {
		returned <- st.Settle(Resolution{Token: held, Verdict: VerdictDrop})
		return Decision{Action: Accept}
	})
	select {
	case errs := <-returned:
		if errs[0] != nil {
			t.Fatalf("Settle = %v", errs[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Settle blocked on OnVerdict: it ran on the caller's stack")
	}
	if !reflect.DeepEqual(kernel, []kernelVerdict{{1, VerdictDrop}, {2, VerdictAccept}}) {
		t.Fatalf("kernel = %+v", kernel)
	}
	close(release)
	comp.flush()
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(got, []Token{held}) {
		t.Fatalf("OnVerdict tokens = %v", got)
	}
}

func TestInlineSettleBatchDropsFirstAndMergesDuplicates(t *testing.T) {
	fx := newInlineFixture(t)
	t1, t2, t3 := fx.hold(1), fx.hold(2), fx.hold(3)
	errs := fx.settler.Settle(
		Resolution{Token: t1, Verdict: VerdictAccept},
		Resolution{Token: t2, Verdict: VerdictAccept},
		Resolution{Token: t3, Verdict: VerdictDrop},
		Resolution{Token: t2, Verdict: VerdictDrop},
	)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	wantKernel := []kernelVerdict{{2, VerdictDrop}, {3, VerdictDrop}, {1, VerdictAccept}}
	if got := fx.kernelVerdicts(); !reflect.DeepEqual(got, wantKernel) {
		t.Fatalf("kernel = %+v, want %+v", got, wantKernel)
	}
	if got := fx.completions(); len(got) != 3 {
		t.Fatalf("completions = %+v, want one per token", got)
	}
}

func TestInlineSettleRejections(t *testing.T) {
	fx := newInlineFixture(t)
	old := fx.hold(1)
	fx.gen.close(nil)
	fx.gen = fx.newGeneration()
	held := fx.hold(1)
	cases := []struct {
		name string
		r    Resolution
		want error
	}{
		{"invalid verdict", Resolution{Token: held, Verdict: 0}, ErrInvalidVerdict},
		{"verdict out of range", Resolution{Token: held, Verdict: 4}, ErrInvalidVerdict},
		{"zero token", Resolution{Verdict: VerdictDrop}, ErrNotInline},
		{"stale generation", Resolution{Token: old, Verdict: VerdictDrop}, ErrStaleToken},
		{"unknown id", Resolution{Token: Token{gen: fx.gen.id, id: 99}, Verdict: VerdictDrop}, ErrUnknownToken},
		{"future generation", Resolution{Token: Token{gen: fx.gen.id + 1000, id: 1}, Verdict: VerdictDrop}, ErrUnknownToken},
	}
	before := len(fx.completions())
	for _, tc := range cases {
		if errs := fx.settler.Settle(tc.r); !errors.Is(errs[0], tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, errs[0], tc.want)
		}
	}
	if got := fx.completions(); len(got) != before {
		t.Fatalf("rejected requests produced completions: %+v", got[before:])
	}
	if got := fx.kernelVerdicts(); len(got) != 0 {
		t.Fatalf("rejected requests submitted %+v", got)
	}
	if errs := fx.settler.Settle(Resolution{Token: held, Verdict: VerdictAccept}); errs[0] != nil {
		t.Fatalf("held token still settles after rejections: %v", errs[0])
	}
}

func TestInlineSettlerBeforeBindAndObservational(t *testing.T) {
	tok := NewToken(nextGeneration(), 1)
	if errs := (&settler{inline: true}).Settle(Resolution{Token: tok, Verdict: VerdictAccept}); !errors.Is(errs[0], ErrQueueClosed) {
		t.Fatalf("unbound = %v, want ErrQueueClosed", errs[0])
	}
	if errs := (&settler{}).Settle(Resolution{Token: tok, Verdict: VerdictAccept}); !errors.Is(errs[0], ErrNotInline) {
		t.Fatalf("observational = %v, want ErrNotInline", errs[0])
	}
}

// Closing a generation completes every outstanding token with
// (Drop, ErrQueueClosed), then reports the source down.
func TestInlineCloseCompletesOutstandingThenDown(t *testing.T) {
	fx := newInlineFixture(t)
	t1, t2 := fx.hold(5), fx.hold(3)
	fx.deliver(4, func(Packet) Decision { return Decision{Action: Accept} })
	cause := errors.New("netlink receive failed")
	fx.gen.close(cause)
	got := fx.completions()
	want := []completionRecord{
		{tok: t2, v: VerdictDrop, err: ErrQueueClosed},
		{tok: t1, v: VerdictDrop, err: ErrQueueClosed},
		{source: &SourceEvent{Generation: fx.gen.id, Err: cause}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("completions = %+v, want %+v", got, want)
	}
	if errs := fx.settler.Settle(Resolution{Token: t1, Verdict: VerdictAccept}); !errors.Is(errs[0], ErrQueueClosed) {
		t.Fatalf("Settle after close = %v, want ErrQueueClosed", errs[0])
	}
	fx.gen.close(nil) // idempotent
	if again := fx.completions(); len(again) != len(want) {
		t.Fatalf("second close produced completions: %+v", again[len(want):])
	}
}

func TestInlineCleanCloseReportsQueueClosed(t *testing.T) {
	fx := newInlineFixture(t)
	fx.gen.close(nil)
	got := fx.completions()
	if len(got) != 1 || got[0].source == nil || got[0].source.Ready || !errors.Is(got[0].source.Err, ErrQueueClosed) {
		t.Fatalf("completions = %+v, want one down event with ErrQueueClosed", got)
	}
}

// A failed submission is reported through OnVerdict, even for an
// immediate accept, and fails the source.
func TestInlineSubmitErrorReportsAndFailsSource(t *testing.T) {
	fx := newInlineFixture(t)
	sendErr := errors.New("sendmsg: no buffer space")
	fx.submitErr[1] = sendErr
	tok := fx.deliver(1, func(Packet) Decision { return Decision{Action: Accept} })
	got := fx.completions()
	if len(got) != 1 || got[0].tok != tok || got[0].v != VerdictAccept || !errors.Is(got[0].err, sendErr) {
		t.Fatalf("completions = %+v, want one failed accept", got)
	}
	if !errors.Is(fx.gen.failure(), sendErr) {
		t.Fatalf("failure = %v, want the submit error", fx.gen.failure())
	}

	held := fx.hold(2)
	fx.submitErr[2] = sendErr
	if errs := fx.settler.Settle(Resolution{Token: held, Verdict: VerdictDrop}); !errors.Is(errs[0], sendErr) {
		t.Fatalf("Settle = %v, want the submit error", errs[0])
	}
}

func TestInlineInvalidDispositionDropsAndReports(t *testing.T) {
	fx := newInlineFixture(t)
	tok := fx.deliver(1, func(Packet) Decision { return Decision{Action: Disposition(9)} })
	if got := fx.completions(); !reflect.DeepEqual(got, []completionRecord{verdictOf(tok, VerdictDrop)}) {
		t.Fatalf("completions = %+v", got)
	}
	if errs := fx.reported(); len(errs) != 1 || !errors.Is(errs[0], errInvalidDisposition) {
		t.Fatalf("reported = %v", errs)
	}
}

func TestInlineResolvedRejectionsAreReported(t *testing.T) {
	fx := newInlineFixture(t)
	fx.deliver(1, func(Packet) Decision {
		return Decision{Action: Accept, Resolved: []Resolution{
			{Token: Token{gen: fx.gen.id, id: 42}, Verdict: VerdictAccept},
			{Token: NewToken(fx.gen.id, 43), Verdict: 0},
		}}
	})
	errs := fx.reported()
	if len(errs) != 2 || !errors.Is(errs[0], ErrUnknownToken) || !errors.Is(errs[1], ErrInvalidVerdict) {
		t.Fatalf("reported = %v", errs)
	}
	if got := fx.completions(); len(got) != 0 {
		t.Fatalf("rejected resolutions produced completions: %+v", got)
	}
}

func TestInlineDuplicatePacketIDFailsSource(t *testing.T) {
	fx := newInlineFixture(t)
	fx.hold(1)
	called := false
	fx.gen.deliver(1, Packet{}, func(Packet) Decision { called = true; return Decision{} })
	if called || fx.gen.failure() == nil {
		t.Fatalf("duplicate id: handler called=%v failure=%v", called, fx.gen.failure())
	}
}

func TestInlineGenerationsAreUniqueAndIncreasing(t *testing.T) {
	fx := newInlineFixture(t)
	a := fx.gen.id
	b := fx.newGeneration().id
	if a == 0 || b <= a {
		t.Fatalf("generations %d then %d", a, b)
	}
}

// Overflowing the completion queue fails the source; nothing is dropped.
func TestInlineCompletionOverflowFailsSourceWithoutLoss(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	delivered := 0
	comp := newCompleter(func(Token, Verdict, error) {
		<-release
		mu.Lock()
		delivered++
		mu.Unlock()
	}, func(SourceEvent) {
		mu.Lock()
		delivered++
		mu.Unlock()
	})
	defer comp.close()
	g := newGeneration(func(uint32, Verdict, uint32) error { return nil }, comp, nil)
	n := completionLimit + 2
	for i := 0; i < n; i++ {
		g.deliver(uint32(i), Packet{}, func(Packet) Decision { return Decision{Action: Drop} })
	}
	if !errors.Is(g.failure(), errCompletionOverflow) {
		t.Fatalf("failure = %v, want overflow", g.failure())
	}
	g.close(g.failure())
	close(release)
	comp.flush()
	mu.Lock()
	defer mu.Unlock()
	if delivered != n+1 {
		t.Fatalf("delivered %d completions, want %d (every drop plus the down event)", delivered, n+1)
	}
}

// Concurrent Settle, decisions and close still give every token exactly
// one completion.
func TestInlineExactlyOnceUnderConcurrency(t *testing.T) {
	for round := 0; round < 20; round++ {
		fx := newInlineFixture(t)
		const held = 64
		toks := make([]Token, held)
		for i := range toks {
			toks[i] = fx.hold(uint32(i))
		}
		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := w; i < held; i += 2 {
					v := VerdictAccept
					if i%3 == 0 {
						v = VerdictDrop
					}
					fx.settler.Settle(Resolution{Token: toks[i], Verdict: v})
				}
			}(w)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fx.deliver(held, func(Packet) Decision {
				return Decision{Action: Hold, Resolved: []Resolution{{Token: toks[1], Verdict: VerdictDrop}, {Token: toks[2], Verdict: VerdictAccept}}}
			})
			fx.gen.close(nil)
		}()
		wg.Wait()
		counts := map[Token]int{}
		downs := 0
		for _, c := range fx.completions() {
			if c.source != nil {
				downs++
				continue
			}
			counts[c.tok]++
		}
		for _, tok := range append(toks, Token{gen: fx.gen.id, id: held}) {
			if counts[tok] != 1 {
				t.Fatalf("round %d: token %v completed %d times", round, tok, counts[tok])
			}
		}
		if downs != 1 || len(counts) != held+1 {
			t.Fatalf("round %d: downs=%d tokens=%d", round, downs, len(counts))
		}
	}
}

func TestVerdictString(t *testing.T) {
	for v, want := range map[Verdict]string{VerdictAccept: "accept", VerdictDrop: "drop", 0: "invalid(0)"} {
		if got := fmt.Sprint(v); got != want {
			t.Fatalf("%d.String() = %q, want %q", v, got, want)
		}
	}
}
