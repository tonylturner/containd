// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"context"
	"fmt"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
)

// nfqueueSource captures packets via NFQUEUE and delivers them to a Handler.
type nfqueueSource struct {
	queueID int
	cfg     Config
	handler Handler

	// runFn lets tests inject a fake inner-loop implementation. Production
	// uses s.run (the real go-nfqueue consumer). Tests override this to
	// exercise the supervise retry/backoff/give-up logic without needing
	// the netfilter kernel surface.
	runFn func(context.Context) error
}

// Bounded retry envelope for the NFQUEUE consumer goroutine. If the
// inner run loop panics or returns an error, restart with exponential
// backoff up to maxRetries; after that, give up and leave the queue
// dark (logged via OnError) so we don't pathologically spin on a
// permanent kernel-side failure. Each successful run that exits via
// ctx-cancel resets the retry counter.
//
// These are vars rather than consts so the tests can compress the
// backoff to sub-millisecond and finish in well under a second
// rather than the production envelope's ~62s worst case.
var (
	nfqueueRetryInitial = 250 * time.Millisecond
	nfqueueRetryMax     = 30 * time.Second
	nfqueueMaxRetries   = 8
)

// withFastBackoff swaps the package-level backoff for fast values
// suitable for unit tests and returns a deferred reset. Used in
// nfqueue_linux_test.go.
func withFastBackoff(d time.Duration) func() {
	prevInit, prevMax := nfqueueRetryInitial, nfqueueRetryMax
	nfqueueRetryInitial = d
	nfqueueRetryMax = d
	return func() {
		nfqueueRetryInitial = prevInit
		nfqueueRetryMax = prevMax
	}
}

func (m *Manager) startNFQueue(ctx context.Context, handler Handler) error {
	src := &nfqueueSource{
		queueID: m.cfg.QueueID,
		cfg:     m.cfg,
		handler: handler,
	}
	src.runFn = src.run
	go src.supervise(ctx, m.cfg.OnError)
	return nil
}

// supervise runs the NFQUEUE consumer in a retry loop. Without this,
// a single panic from go-nfqueue/v2 + mdlayher/netlink (observed on
// LinuxKit kernels parsing truncated netlink messages) would silently
// leave the kernel queue undrained — ICS traffic queues to a sink
// nobody reads, and the queue eventually fills (MaxQueueLen=1024)
// and either drops new packets or stalls them until full engine
// restart. The recover here logs the panic via onError, then attempts
// to re-establish the consumer via fresh nfqueue.Open + RegisterWithErrorFunc.
// Bounded retries (nfqueueMaxRetries with exponential backoff) prevent
// a permanent kernel-side failure from busy-looping. Cancellation via
// ctx.Done() exits cleanly without consuming a retry.
func (s *nfqueueSource) supervise(ctx context.Context, onError func(error)) {
	backoff := nfqueueRetryInitial
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		err := s.runWithRecover(ctx, onError)
		if ctx.Err() != nil {
			return
		}
		if err != nil && onError != nil {
			onError(fmt.Errorf("nfqueue consumer exited (attempt %d/%d): %w", attempt+1, nfqueueMaxRetries, err))
		}
		if attempt+1 >= nfqueueMaxRetries {
			if onError != nil {
				onError(fmt.Errorf("nfqueue consumer giving up after %d failed attempts; queue %d will be undrained until engine restart",
					nfqueueMaxRetries, s.queueID))
			}
			return
		}
		// Sleep with cancellation-awareness so a ctx cancel doesn't
		// have to wait out the full backoff before exiting.
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > nfqueueRetryMax {
			backoff = nfqueueRetryMax
		}
	}
}

// runWithRecover converts a panic in runFn() into a returned error so
// supervise() can retry it the same way it retries normal errors.
func (s *nfqueueSource) runWithRecover(ctx context.Context, onError func(error)) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if onError != nil {
				onError(fmt.Errorf("nfqueue consumer panicked, recovered: %v", r))
			}
			err = fmt.Errorf("nfqueue consumer panic: %v", r)
		}
	}()
	return s.runFn(ctx)
}

func (s *nfqueueSource) run(ctx context.Context) error {
	cfg := nfqueue.Config{
		NfQueue:      uint16(s.queueID),
		MaxPacketLen: uint32(s.cfg.Snaplen),
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		return fmt.Errorf("nfqueue open queue %d: %w", s.queueID, err)
	}
	// Unconditional release so that ANY return path — normal ctx
	// cancel, register error, or a panic propagating up through
	// runWithRecover — closes the netfilter group binding before
	// supervise's retry calls nfqueue.Open again. Without this,
	// the old binding sat with the kernel while supervise burned
	// retries on EBUSY/EPERM Opens, turning panic-recovery into a
	// recover-and-loop-fail loop until the retry envelope gave up.
	// nf.Close is idempotent; safe to defer here even though
	// RegisterWithErrorFunc's internal goroutine also closes on
	// ctx cancel.
	defer func() { _ = nf.Close() }()

	hookFn := func(a nfqueue.Attribute) int {
		if a.Payload == nil || len(*a.Payload) == 0 {
			if a.PacketID != nil {
				_ = nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
			}
			return 0
		}
		pkt, ok := decodeIPPacket(*a.Payload)
		if !ok {
			// Not a parseable IP packet -- accept and move on.
			if a.PacketID != nil {
				_ = nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
			}
			return 0
		}

		// Deliver to capture handler (DPI/telemetry).
		s.handler(pkt)

		// Default verdict is ACCEPT. The verdict cache in the engine will
		// override this via nftables set updates for blocked flows.
		if a.PacketID != nil {
			_ = nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		}
		return 0
	}

	errFn := func(e error) int {
		if s.cfg.OnError != nil {
			s.cfg.OnError(e)
		}
		if ctx.Err() != nil {
			return 1
		}
		return 0
	}

	if err := nf.RegisterWithErrorFunc(ctx, hookFn, errFn); err != nil {
		// nf.Close runs via defer above; no explicit close needed.
		return fmt.Errorf("nfqueue register: %w", err)
	}

	// Block until context is cancelled. nf.Close fires via defer
	// on the way out, which signals RegisterWithErrorFunc's internal
	// goroutine to exit cleanly.
	<-ctx.Done()
	return nil
}
