// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/events"
)

// startNFLogLocked preserves synchronous first registration, with a bounded
// background retry domain independent of capture. lifecycleMu excludes replacement.
func (e *Engine) startNFLogLocked(lifetime context.Context) {
	if e.nflogGroup == 0 || e.nflogStop != nil {
		return
	}
	ctx, cancel := context.WithCancel(lifetime)
	initial, maximum, attempts, start := startRetryInitial, startRetryMax, startRetryAttempts, startNFLog
	done := make(chan struct{})
	var once sync.Once
	e.nflogStop = func() { once.Do(func() { cancel(); <-done }) }
	p, group, onError := e.protection, e.nflogGroup, e.onError
	p.update(func() { p.nflogLost = false })
	set := func(state, reason string, attempt int) {
		p.update(func() {
			max := attempts
			if state == "ready" {
				max = 0
				p.nflogLost = false
			}
			p.setLocked("nflog", state, reason, attempt, max)
		})
	}
	lost := make(chan error, 1)
	bind := func(attempt int) (func(), error) {
		set("pending", "awaiting NFLOG bind", attempt)
		consumerCtx, cancelConsumer := context.WithCancel(ctx)
		var sourceMu sync.Mutex
		dead := false
		stop, err := start(consumerCtx, group, nflogRuleHits{e}, func(error) {}, func(ev capture.SourceEvent) {
			sourceMu.Lock()
			defer sourceMu.Unlock()
			if ev.Terminal && consumerCtx.Err() == nil && !dead {
				dead = true
				p.update(func() {
					p.nflogLost = true
					p.setLocked("nflog", "pending", fmt.Sprintf("nflog:%d: %v", group, ev.Err), 0, attempts)
				})
				select {
				case lost <- ev.Err:
				default:
				}
			}
		})
		sourceMu.Lock()
		if err == nil {
			if !dead {
				set("ready", "", 0)
			}
		} else {
			set("pending", err.Error(), attempt)
			e.eventStore.Append(events.Event{Kind: "service.nflog.unavailable", Timestamp: time.Now().UTC(), Attributes: map[string]any{"group": int(group), "error": err.Error()}})
			if onError != nil {
				onError(fmt.Errorf("nflog group %d unavailable: %w", group, err))
			}
		}
		sourceMu.Unlock()
		if err != nil {
			cancelConsumer()
			stop()
		}
		return func() { cancelConsumer(); stop() }, err
	}
	stop, err := bind(1)
	go func() {
		defer close(done)
		attempt, backoff := 1, initial
		for {
			if err == nil {
				select {
				case <-ctx.Done():
					stop()
					return
				case err = <-lost:
					stop()
				}
				attempt, backoff = 0, initial
			}
			if ctx.Err() != nil {
				return
			}
			if attempt >= attempts {
				set("failed", fmt.Sprintf("nflog:%d: %v", group, err), attempt)
				return
			}
			set("pending", fmt.Sprintf("nflog:%d: %v", group, err), attempt)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			backoff = min(2*backoff, maximum)
			attempt++
			stop, err = bind(attempt)
		}
	}()
}

func (e *Engine) stopNFLogLocked() {
	if e.nflogStop != nil {
		e.nflogStop()
		e.nflogStop = nil
	}
}

func (e *Engine) retryNFLogLocked(ctx context.Context, retryPending bool) {
	p := e.protection
	p.mu.Lock()
	state := p.components["nflog"].State
	p.mu.Unlock()
	if state == "failed" || state == "pending" && (e.nflogStop == nil || retryPending) {
		e.stopNFLogLocked()
		e.startNFLogLocked(ctx)
	}
}
