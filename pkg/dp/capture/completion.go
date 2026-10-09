// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"errors"
	"sync"
)

// completionLimit bounds undelivered completions. Exceeding it is a source
// failure: the generation goes down, so the queue stops growing. Nothing
// already queued is discarded.
const completionLimit = 4096

var errCompletionOverflow = errors.New("capture: verdict completion queue overflow")

// completion is one OnVerdict or OnSource call.
type completion struct {
	source  bool
	tok     Token
	verdict Verdict
	err     error
	event   SourceEvent
}

// completer runs OnVerdict and OnSource on one goroutine, in push order.
type completer struct {
	onVerdict VerdictFunc
	onSource  func(SourceEvent)

	mu        sync.Mutex
	cond      *sync.Cond // queue, delivered or closed changed
	queue     []completion
	queued    uint64
	delivered uint64
	closed    bool
	done      chan struct{}
}

func newCompleter(onVerdict VerdictFunc, onSource func(SourceEvent)) *completer {
	c := &completer{onVerdict: onVerdict, onSource: onSource, done: make(chan struct{})}
	c.cond = sync.NewCond(&c.mu)
	go c.run()
	return c
}

// push queues x and reports whether undelivered completions now exceed
// completionLimit. It never blocks and never drops x.
func (c *completer) push(x completion) (overflow bool) {
	c.mu.Lock()
	c.queue = append(c.queue, x)
	c.queued++
	pending := c.queued - c.delivered
	c.mu.Unlock()
	c.cond.Broadcast()
	return pending > completionLimit
}

// flush waits until everything pushed before the call has been delivered.
// It must not run on the completion goroutine.
func (c *completer) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	target := c.queued
	for c.delivered < target {
		c.cond.Wait()
	}
}

// close delivers everything queued, then stops the goroutine.
func (c *completer) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cond.Broadcast()
	<-c.done
}

func (c *completer) run() {
	defer close(c.done)
	for {
		c.mu.Lock()
		for len(c.queue) == 0 && !c.closed {
			c.cond.Wait()
		}
		batch := c.queue
		c.queue = nil
		c.mu.Unlock()
		if len(batch) == 0 {
			return // closed and drained
		}
		for _, x := range batch {
			c.deliver(x)
		}
		c.mu.Lock()
		c.delivered += uint64(len(batch))
		c.mu.Unlock()
		c.cond.Broadcast()
	}
}

func (c *completer) deliver(x completion) {
	switch {
	case x.source && c.onSource != nil:
		c.onSource(x.event)
	case !x.source && c.onVerdict != nil:
		c.onVerdict(x.tok, x.verdict, x.err)
	}
}
