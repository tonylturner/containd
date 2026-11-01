// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// First-bind retry bounds. They match the 0.1.31 NFQUEUE supervisor (250 ms
// doubling to 30 s, 8 attempts), which retried a failed first bind in the
// background before Start was made to report it.
var (
	startRetryInitial  = 250 * time.Millisecond
	startRetryMax      = 30 * time.Second
	startRetryAttempts = 8
)

// errStartSuperseded reports a retry loop whose configuration was replaced.
var errStartSuperseded = errors.New("engine: start superseded by reconfigure")

// StartWithRetry starts the data plane. An inline (NFQUEUE) engine whose
// queue fails to bind retries with bounded exponential backoff; while it is
// unbound the queue-bind health fault stands, so IEC104 enforcement reports
// unhealthy and envelope traffic fails closed in the kernel. A
// Reconfigure ends the loop: the new configuration starts its own. Other
// capture modes start once, as before.
func (e *Engine) StartWithRetry(ctx context.Context) error {
	return e.StartProtection(ctx, ctx)
}

// StartProtection separates retry cancellation from the adopted run lifetime.
func (e *Engine) StartProtection(ctx, lifetime context.Context) error {
	e.lifecycleMu.Lock()
	epoch, onError := e.epoch.Load(), e.onError
	e.lifecycleMu.Unlock()
	backoff := startRetryInitial
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		group, err := e.start(lifetime)
		e.protection.bindAttempt(epoch, group, err, attempt, startRetryAttempts)
		if err == nil || group == 0 {
			return err
		}
		if attempt >= startRetryAttempts {
			return fmt.Errorf("nfqueue %d: giving up after %d bind attempts: %w", group, attempt, err)
		}
		if onError != nil {
			onError(fmt.Errorf("nfqueue %d bind failed (attempt %d/%d), retrying in %s: %w", group, attempt, startRetryAttempts, backoff, err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if e.epoch.Load() != epoch {
			return errStartSuperseded
		}
		backoff = min(backoff*2, startRetryMax)
	}
}
