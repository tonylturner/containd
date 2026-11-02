// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"sync"
	"time"
)

const sessionStatusInterval = 5 * time.Second

// SessionStatusPoller keeps advisory status requests off the command/input path.
// A refresh immediately invalidates the previous clean/dirty claim. Only a
// response from the current generation may restore it.
type SessionStatusPoller struct {
	mu         sync.Mutex
	api        API
	status     SessionStatus
	generation uint64
	refresh    chan struct{}
	updates    chan struct{}
	cancel     context.CancelFunc
	done       chan struct{}
}

func NewSessionStatusPoller(ctx context.Context, api *API) *SessionStatusPoller {
	ticker := time.NewTicker(sessionStatusInterval)
	return newSessionStatusPoller(ctx, api, ticker.C, ticker.Stop)
}

func newSessionStatusPoller(ctx context.Context, api *API, ticks <-chan time.Time, stop func()) *SessionStatusPoller {
	ctx, cancel := context.WithCancel(ctx)
	p := &SessionStatusPoller{
		refresh: make(chan struct{}, 1), updates: make(chan struct{}, 1),
		cancel: cancel, done: make(chan struct{}),
	}
	p.Refresh(api)
	go p.run(ctx, ticks, stop)
	return p
}

// Refresh is called by the command owner after commands, including failures:
// a failed response does not prove that no mutation took place. Copy credentials
// on this caller's goroutine; the worker never reads or rotates the command API.
func (p *SessionStatusPoller) Refresh(api *API) {
	p.mu.Lock()
	p.api = API{BaseURL: api.BaseURL, Client: api.Client, Token: api.Token}
	p.generation++
	p.status = SessionStatus{Error: "Refreshing candidate status"}
	p.mu.Unlock()
	p.notify()
	select {
	case p.refresh <- struct{}{}:
	default:
	}
}

func (p *SessionStatusPoller) Snapshot() SessionStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// SyncToken lets the command owner adopt credentials renewed by idle polling
// before executing its next command. The worker never writes to that API.
func (p *SessionStatusPoller) SyncToken(api *API) {
	p.mu.Lock()
	defer p.mu.Unlock()
	api.Token = p.api.Token
}

// Updates wakes a terminal owner. Only that owner may redraw its input.
func (p *SessionStatusPoller) Updates() <-chan struct{} { return p.updates }

func (p *SessionStatusPoller) Close() {
	p.cancel()
	<-p.done
}

func (p *SessionStatusPoller) notify() {
	select {
	case p.updates <- struct{}{}:
	default:
	}
}

func (p *SessionStatusPoller) run(ctx context.Context, ticks <-chan time.Time, stop func()) {
	defer close(p.done)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.refresh:
		case <-ticks:
		}
		if ctx.Err() != nil {
			return
		}
		p.mu.Lock()
		api, generation := p.api, p.generation
		p.status = SessionStatus{Error: "Refreshing candidate status"}
		p.mu.Unlock()
		p.notify()
		status := api.SessionStatus(ctx)
		p.mu.Lock()
		if generation == p.generation {
			p.status = status
			p.api.Token = api.Token
		}
		p.mu.Unlock()
		p.notify()
	}
}
