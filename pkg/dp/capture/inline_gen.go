// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

var errInvalidDisposition = errors.New("capture: handler returned an invalid disposition")

// generation is one bound lifetime of an inline queue. It owns the tokens
// it delivered: each is outstanding from just before its handler call until
// its verdict is submitted or the generation closes, and each gets at most
// one completion.
type generation struct {
	id      uint64
	submit  func(id uint32, v Verdict) error // kernel verdict; nil = submitted
	comp    *completer
	onError func(error)

	failOnce sync.Once
	failErr  error
	failed   chan struct{} // closed by fail

	mu          sync.Mutex
	outstanding map[uint32]*pending
	closed      bool
	inflight    sync.WaitGroup // claimed tokens whose submission is in progress
}

// pending is one outstanding token.
type pending struct {
	inCallback bool    // its handler call has not returned yet
	staged     Verdict // Settle request received during the callback; 0 = none
}

// submission is one verdict to submit. notify is true when OnVerdict must
// report it even on success.
type submission struct {
	tok    Token
	v      Verdict
	notify bool
	reqs   []int // Settle request indexes it answers
}

func newGeneration(submit func(uint32, Verdict) error, comp *completer, onError func(error)) *generation {
	return &generation{
		id:          nextGeneration(),
		submit:      submit,
		comp:        comp,
		onError:     onError,
		failed:      make(chan struct{}),
		outstanding: make(map[uint32]*pending),
	}
}

// fail marks the source failed with err; the first error wins. The owner
// watches failed and closes the generation. fail never blocks.
func (g *generation) fail(err error) {
	g.failOnce.Do(func() {
		g.failErr = err
		close(g.failed)
	})
}

// failure returns the error passed to fail, or nil.
func (g *generation) failure() error {
	select {
	case <-g.failed:
		return g.failErr
	default:
		return nil
	}
}

func (g *generation) reportError(err error) {
	if g.onError != nil {
		g.onError(err)
	}
}

func (g *generation) push(x completion) {
	if g.comp.push(x) {
		g.fail(errCompletionOverflow)
	}
}

// deliver registers packet id as outstanding, runs the handler without any
// capture lock held, and applies its Decision.
func (g *generation) deliver(id uint32, pkt Packet, h Handler) {
	tok := Token{gen: g.id, id: id}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	if _, dup := g.outstanding[id]; dup {
		g.mu.Unlock()
		// A wrapped packet ID would break exactly-once; the kernel drops the
		// undelivered packet when the generation closes.
		g.fail(fmt.Errorf("capture: packet id %d delivered twice in generation %d", id, g.id))
		return
	}
	g.outstanding[id] = &pending{inCallback: true}
	g.mu.Unlock()

	pkt.Token = tok
	g.finish(tok, h(pkt))
}

// finish applies the Decision for tok: the current packet, its staged
// Settle requests and the earlier tokens it resolves form one batch whose
// Drops are submitted before its Accepts.
func (g *generation) finish(tok Token, d Decision) {
	var rejected []error
	g.mu.Lock()
	p := g.outstanding[tok.id]
	if p == nil || g.closed {
		g.mu.Unlock()
		return
	}
	p.inCallback = false

	var subs []submission
	index := map[uint32]int{}
	for _, r := range d.Resolved {
		if err := routeError(true, g, r); err != nil {
			rejected = append(rejected, fmt.Errorf("capture: resolve %s: %w", r.Token, err))
			continue
		}
		if r.Token == tok {
			p.staged = dropWins(p.staged, r.Verdict)
			continue
		}
		if _, ok := g.outstanding[r.Token.id]; !ok {
			rejected = append(rejected, fmt.Errorf("capture: resolve %s: %w", r.Token, ErrUnknownToken))
			continue
		}
		subs = mergeSubmission(subs, index, submission{tok: r.Token, v: r.Verdict, notify: true})
	}
	cur, submitCur, err := currentVerdict(d.Action, p.staged)
	if err != nil {
		rejected = append(rejected, fmt.Errorf("capture: %s disposition %d: %w", tok, d.Action, err))
	}
	if submitCur {
		subs = append([]submission{cur}, subs...)
		subs[0].tok = tok
	}
	for _, s := range subs {
		delete(g.outstanding, s.tok.id)
	}
	g.inflight.Add(1)
	g.mu.Unlock()

	for _, err := range rejected {
		g.reportError(err)
	}
	g.submitAll(subs, nil)
	g.inflight.Done()
}

// currentVerdict combines the handler's disposition with a verdict staged
// by Settle during the callback. Drop wins; Hold without a staged verdict
// leaves the token outstanding.
func currentVerdict(action Disposition, staged Verdict) (submission, bool, error) {
	var s submission
	var err error
	switch action {
	case Accept:
		s.v = VerdictAccept
	case Drop:
		s.v, s.notify = VerdictDrop, true
	case Hold:
		if staged == 0 {
			return s, false, nil
		}
		s.v = staged
	default:
		s.v, s.notify, err = VerdictDrop, true, errInvalidDisposition
	}
	if staged != 0 {
		s.v, s.notify = dropWins(s.v, staged), true
	}
	return s, true, err
}

func dropWins(a, b Verdict) Verdict {
	if a == VerdictDrop || b == VerdictDrop {
		return VerdictDrop
	}
	if a == 0 {
		return b
	}
	return a
}

// mergeSubmission adds s, or folds it into an earlier submission for the
// same token (Drop wins over an Accept not yet submitted).
func mergeSubmission(subs []submission, index map[uint32]int, s submission) []submission {
	if j, ok := index[s.tok.id]; ok {
		subs[j].v = dropWins(subs[j].v, s.v)
		subs[j].reqs = append(subs[j].reqs, s.reqs...)
		return subs
	}
	index[s.tok.id] = len(subs)
	return append(subs, s)
}

// settle handles the Settle requests res[i] for i in idxs, all routed to
// this generation, and fills errs.
func (g *generation) settle(res []Resolution, idxs []int, errs []error) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		for _, i := range idxs {
			errs[i] = ErrQueueClosed
		}
		return
	}
	var subs []submission
	index := map[uint32]int{}
	for _, i := range idxs {
		r := res[i]
		p, ok := g.outstanding[r.Token.id]
		switch {
		case !ok:
			errs[i] = ErrUnknownToken
		case p.inCallback:
			p.staged = dropWins(p.staged, r.Verdict)
		default:
			subs = mergeSubmission(subs, index, submission{tok: r.Token, v: r.Verdict, notify: true, reqs: []int{i}})
		}
	}
	for _, s := range subs {
		delete(g.outstanding, s.tok.id)
	}
	g.inflight.Add(1)
	g.mu.Unlock()

	g.submitAll(subs, errs)
	g.inflight.Done()
}

// submitAll submits Drops before Accepts, keeping order within each class.
// A failed submission is reported through OnVerdict and fails the source:
// the packet may still sit in the kernel queue, and only closing the queue
// is sure to drop it.
func (g *generation) submitAll(subs []submission, errs []error) {
	sort.SliceStable(subs, func(i, j int) bool {
		return subs[i].v == VerdictDrop && subs[j].v != VerdictDrop
	})
	for _, s := range subs {
		err := g.submit(s.tok.id, s.v)
		if err != nil {
			err = fmt.Errorf("capture: submit %s for %s: %w", s.v, s.tok, err)
			g.fail(err)
		}
		for _, i := range s.reqs {
			errs[i] = err
		}
		if s.notify || err != nil {
			g.push(completion{tok: s.tok, verdict: s.v, err: err})
		}
	}
}

// close ends the generation after its packet source has stopped. Every
// token still outstanding gets (VerdictDrop, ErrQueueClosed): the kernel
// drops queued packets when the queue socket closes. The down event follows
// those completions and any in-flight submission's completion.
func (g *generation) close(cause error) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	ids := make([]uint32, 0, len(g.outstanding))
	for id := range g.outstanding {
		ids = append(ids, id)
	}
	g.outstanding = nil
	g.mu.Unlock()

	g.inflight.Wait()
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		g.push(completion{tok: Token{gen: g.id, id: id}, verdict: VerdictDrop, err: ErrQueueClosed})
	}
	if cause == nil {
		cause = ErrQueueClosed
	}
	g.push(completion{source: true, event: SourceEvent{Generation: g.id, Err: cause}})
}
