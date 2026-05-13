// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNFQueueSuperviseRestartsAfterPanic asserts that supervise() does
// NOT silently exit when the inner runFn panics — it must recover and
// restart the consumer. Without this, a single bad netlink message
// would permanently dark-park the NFQUEUE consumer and ICS traffic
// would queue to nowhere until engine restart (Codex review on PR
// #21 caught the original recover-without-restart as a P1).
func TestNFQueueSuperviseRestartsAfterPanic(t *testing.T) {
	var attempts atomic.Int32
	src := &nfqueueSource{queueID: 100}
	src.runFn = func(ctx context.Context) error {
		n := attempts.Add(1)
		if n == 1 {
			panic("simulated netlink slice-bounds panic")
		}
		// On the restart, run cleanly until cancelled — proves the
		// supervisor reaches the second attempt rather than exiting
		// on the panic.
		<-ctx.Done()
		return nil
	}

	var errs []error
	var errMu sync.Mutex
	onErr := func(e error) {
		errMu.Lock()
		defer errMu.Unlock()
		errs = append(errs, e)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		src.supervise(ctx, onErr)
		close(done)
	}()
	// Give it long enough to: panic on attempt 1, sleep the initial
	// backoff (250ms), restart on attempt 2.
	deadline := time.After(3 * time.Second)
	for {
		if attempts.Load() >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected at least 2 attempts after panic+restart, got %d", attempts.Load())
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	<-done

	if got := attempts.Load(); got < 2 {
		t.Errorf("expected runFn invoked >=2 times (panic then restart), got %d", got)
	}
	errMu.Lock()
	sawPanicReport := false
	for _, e := range errs {
		if e == nil || errors.Is(e, context.Canceled) {
			continue
		}
		if strings.Contains(e.Error(), "panicked") {
			sawPanicReport = true
		}
	}
	errMu.Unlock()
	if !sawPanicReport {
		t.Error("expected onError to receive a 'panicked, recovered' notification")
	}
}

// TestNFQueueSuperviseGivesUpAfterMaxRetries asserts the bounded
// retry envelope. A permanently-broken kernel-side surface should NOT
// cause the goroutine to busy-loop forever; after nfqueueMaxRetries
// attempts the supervisor logs a "giving up" message and exits.
//
// We override the package-level backoff constants for the duration of
// this test to keep total runtime under a second — production values
// (250ms → 30s exponential) would make the test take ~60s.
func TestNFQueueSuperviseGivesUpAfterMaxRetries(t *testing.T) {
	// Save + restore the production backoff so other tests aren't
	// affected. (We can't shrink a const, but we CAN swap variable
	// values — the constants are only consulted at the call site,
	// so this works via the wrapper below.)
	defer withFastBackoff(1 * time.Millisecond)()

	var attempts atomic.Int32
	src := &nfqueueSource{queueID: 100}
	src.runFn = func(ctx context.Context) error {
		attempts.Add(1)
		return fmt.Errorf("simulated permanent failure")
	}

	var gaveUp atomic.Bool
	onErr := func(e error) {
		if e != nil && strings.Contains(e.Error(), "giving up") && strings.Contains(e.Error(), "engine restart") {
			gaveUp.Store(true)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		src.supervise(ctx, onErr)
		close(done)
	}()

	select {
	case <-done:
		if got := attempts.Load(); got != int32(nfqueueMaxRetries) {
			t.Errorf("expected exactly %d attempts before giveup, got %d", nfqueueMaxRetries, got)
		}
		if !gaveUp.Load() {
			t.Error("expected onError to receive a 'giving up' message")
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("supervise did not give up within the (fast-backoff) retry envelope")
	}
}

// TestNFQueueSuperviseCleansUpBetweenRetries asserts that the
// supervise loop does not call runFn while a previous attempt's
// kernel-side resource is still held. With the `defer nf.Close()`
// fix, a panic in run() unwinds the deferred close before
// runWithRecover returns, so by the time supervise calls runFn
// again the handle is gone. We model this here by having the fake
// runFn observe an "in-flight" flag — if supervise re-entered
// runFn before the previous attempt's defer ran, the flag would
// still be true and we'd fail the test. (Codex review on PR #22
// caught the original missing-defer as P1: it kept the kernel
// binding alive across retries, so each retry's nfqueue.Open hit
// EBUSY and the consumer never recovered.)
func TestNFQueueSuperviseCleansUpBetweenRetries(t *testing.T) {
	defer withFastBackoff(1 * time.Millisecond)()

	var inFlight atomic.Bool
	var overlap atomic.Bool
	var calls atomic.Int32

	src := &nfqueueSource{queueID: 100}
	src.runFn = func(ctx context.Context) error {
		// If supervise re-entered before the previous attempt's
		// defer chain finished, inFlight is still true.
		if inFlight.Load() {
			overlap.Store(true)
		}
		inFlight.Store(true)
		// Deferred reset stands in for the real defer nf.Close().
		// Production: defer fires when run() unwinds (including
		// panic-via-recover).
		defer inFlight.Store(false)

		n := calls.Add(1)
		switch n {
		case 1:
			panic("simulated panic mid-flight")
		case 2:
			return fmt.Errorf("simulated error")
		default:
			// Third attempt: run cleanly until cancel.
			<-ctx.Done()
			return nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		src.supervise(ctx, func(error) {})
		close(done)
	}()
	deadline := time.After(3 * time.Second)
	for calls.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("expected runFn called >=3 times, got %d", calls.Load())
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-done

	if overlap.Load() {
		t.Error("supervise re-entered runFn while a previous attempt was still in-flight " +
			"— defer cleanup must complete before the retry restarts")
	}
}

// TestNFQueueSuperviseExitsOnContextCancel confirms a clean exit on
// ctx.Done() doesn't consume a retry slot — student stopping the lab
// shouldn't spam onError with 'attempt N/M failed' messages.
func TestNFQueueSuperviseExitsOnContextCancel(t *testing.T) {
	defer withFastBackoff(1 * time.Millisecond)()

	src := &nfqueueSource{queueID: 100}
	src.runFn = func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}

	var errCount atomic.Int32
	onErr := func(e error) { errCount.Add(1) }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		src.supervise(ctx, onErr)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervise did not exit promptly on ctx cancel")
	}
	if errCount.Load() > 0 {
		t.Errorf("expected zero error notifications on clean cancel, got %d", errCount.Load())
	}
}
