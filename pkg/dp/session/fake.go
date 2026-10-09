// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package session

import (
	"net"
	"sync"
)

// Fake is an in-memory Injector for tests. It records every SendRST
// attempt, including failed ones, and returns the configured error. It is
// safe for concurrent use.
type Fake struct {
	mu     sync.Mutex
	err    error
	resets []Reset
	closed bool
}

var _ Injector = (*Fake)(nil)

// SetError makes later SendRST calls return err (nil restores success).
func (f *Fake) SetError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// SendRST records r and returns the configured error, or net.ErrClosed
// after Close.
func (f *Fake) SendRST(r Reset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	f.resets = append(f.resets, r)
	return f.err
}

// Close marks the fake closed.
func (f *Fake) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// Resets returns a copy of the recorded resets in call order.
func (f *Fake) Resets() []Reset {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Reset(nil), f.resets...)
}

// Closed reports whether Close was called.
func (f *Fake) Closed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}
