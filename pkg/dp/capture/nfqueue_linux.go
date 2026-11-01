// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

// inlineMaxPacketLen copies whole packets to userspace: an inline verdict
// must judge every payload byte.
const inlineMaxPacketLen = 65535

// nfqueueSource captures packets via NFQUEUE and delivers them inline: the
// handler's Decision is the packet's verdict.
type nfqueueSource struct {
	generation uint64
	queueID    int
	cfg        Config
	handler    Handler
	settler    *settler
	comp       *completer

	// runFn lets tests inject a fake inner-loop implementation. Production
	// uses s.run (the real go-nfqueue consumer). A run calls ready once its
	// queue is bound and the generation's Ready event is delivered. Tests
	// override this to exercise the supervise retry/backoff/give-up logic
	// without needing the netfilter kernel surface.
	runFn func(ctx context.Context, ready func()) error
}

// Bounded retry envelope for the NFQUEUE consumer goroutine. If the
// inner run loop panics or returns an error, restart with exponential
// backoff; after nfqueueMaxRetries consecutive failures, give up and leave
// the queue dark (logged via OnError) so we don't pathologically spin on a
// permanent kernel-side failure. A run that bound its queue resets the
// failure count and the backoff.
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

// startNFQueue starts the supervised consumer and returns once its first
// queue generation is bound, or with the first bind error.
func (m *Manager) startNFQueue(ctx context.Context, handler Handler) error {
	src := &nfqueueSource{
		queueID: m.cfg.QueueID,
		cfg:     m.cfg,
		handler: handler,
		settler: m.settler,
		comp:    m.comp,
	}
	src.runFn = src.run
	bound := make(chan error, 1)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		src.supervise(ctx, bound)
	}()
	return <-bound
}

// supervise runs the NFQUEUE consumer in a retry loop. Without this,
// a single panic from go-nfqueue/v2 + mdlayher/netlink (observed on
// LinuxKit kernels parsing truncated netlink messages) would silently
// leave the kernel queue undrained — ICS traffic queues to a sink
// nobody reads, and the queue eventually fills (MaxQueueLen=1024)
// and either drops new packets or stalls them until full engine
// restart. The recover here logs the panic via OnError, then attempts
// to re-establish the consumer via fresh nfqueue.Open + RegisterWithErrorFunc.
// Bounded retries (nfqueueMaxRetries with exponential backoff) prevent
// a permanent kernel-side failure from busy-looping. Cancellation via
// ctx.Done() exits cleanly without consuming a retry.
//
// bound receives exactly one value: nil once the first run is bound, or
// the error that ended the first run before it bound. A first run that
// fails is not retried; Start reports its error.
func (s *nfqueueSource) supervise(ctx context.Context, bound chan<- error) {
	onError := s.cfg.OnError
	reported := false
	report := func(err error) {
		if !reported {
			reported = true
			bound <- err
		}
	}
	defer func() { report(context.Cause(ctx)) }()
	backoff := nfqueueRetryInitial
	for failures := 0; ; {
		if ctx.Err() != nil {
			return
		}
		ranBound := false
		err := s.runWithRecover(ctx, func() {
			ranBound = true
			report(nil)
		})
		if !reported {
			if err == nil {
				err = fmt.Errorf("nfqueue queue %d: consumer exited before binding", s.queueID)
			}
			report(err)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if ranBound {
			failures, backoff = 0, nfqueueRetryInitial
		}
		failures++
		if err != nil && onError != nil {
			onError(fmt.Errorf("nfqueue consumer exited (attempt %d/%d): %w", failures, nfqueueMaxRetries, err))
		}
		if s.cfg.OnSource != nil {
			ev := SourceEvent{Generation: s.generation, Err: err, Terminal: failures >= nfqueueMaxRetries, Attempt: failures, MaxAttempts: nfqueueMaxRetries}
			if s.comp != nil {
				s.comp.push(completion{source: true, event: ev})
				s.comp.flush()
			} else {
				s.cfg.OnSource(ev)
			}
		}
		if failures >= nfqueueMaxRetries {
			if onError != nil {
				onError(fmt.Errorf("nfqueue consumer giving up after %d failed attempts; queue %d will be undrained until an explicit retry or reconfiguration",
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
func (s *nfqueueSource) runWithRecover(ctx context.Context, ready func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if s.cfg.OnError != nil {
				s.cfg.OnError(fmt.Errorf("nfqueue consumer panicked, recovered: %v", r))
			}
			err = fmt.Errorf("nfqueue consumer panic: %v", r)
		}
	}()
	return s.runFn(ctx, ready)
}

// run binds one queue generation and serves it until ctx ends or the
// generation fails. The queue socket is closed before the generation's
// close completions and down event are queued, and run returns only after
// they are delivered, so they precede the next generation's first packet.
func (s *nfqueueSource) run(ctx context.Context, ready func()) error {
	cfg := nfqueue.Config{
		NfQueue:      uint16(s.queueID),
		MaxPacketLen: inlineMaxPacketLen,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagConntrack,
	}

	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		return fmt.Errorf("nfqueue open queue %d: %w", s.queueID, err)
	}
	// Unconditional release so that ANY return path — normal ctx
	// cancel, register error, or a panic propagating up through
	// runWithRecover — closes the netfilter group binding before
	// supervise's retry calls nfqueue.Open again. nf.Close is idempotent.
	defer func() { _ = nf.Close() }()

	gen := newGeneration(func(id uint32, v Verdict, mark uint32) error {
		if v == VerdictDrop {
			return nf.SetVerdict(id, nfqueue.NfDrop)
		}
		if v == VerdictRepeat {
			return nf.SetVerdictWithOption(id, nfqueue.NfRepeat, nfqueue.WithMark(mark))
		}
		return nf.SetVerdict(id, nfqueue.NfAccept)
	}, s.comp, s.cfg.OnError)
	s.generation = gen.id
	gen.fence = s.cfg.PublicationFence
	open := make(chan struct{}) // closed once the Ready event is delivered

	hookFn := func(a nfqueue.Attribute) int {
		<-open
		if a.PacketID == nil {
			return 0 // no ID, no verdict possible; nothing to own
		}
		var raw []byte
		if a.Payload != nil {
			raw = *a.Payload
		}
		pkt := DecodeIPPacket(raw)
		pkt.Timestamp = time.Now().UTC()
		pkt.Interface = "nfqueue"
		pkt.Queue = queueMetadata(a)
		if a.Mark != nil {
			pkt.Mark = *a.Mark
			pkt.HasMark = true
		}
		gen.deliver(*a.PacketID, pkt, s.handler)
		return 0
	}

	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	errFn := func(e error) int {
		if runCtx.Err() != nil {
			return 1
		}
		if s.cfg.OnError != nil {
			s.cfg.OnError(e)
		}
		if receiveRecoverable(e) {
			return 0
		}
		gen.fail(fmt.Errorf("nfqueue receive: %w", e))
		return 1
	}

	if err := nf.RegisterWithErrorFunc(runCtx, hookFn, errFn); err != nil {
		// nf.Close runs via defer above; no explicit close needed.
		return fmt.Errorf("nfqueue register: %w", err)
	}

	s.settler.publish(gen)
	gen.push(completion{source: true, event: SourceEvent{Generation: gen.id, Ready: true}})
	s.comp.flush()
	close(open)
	ready()

	select {
	case <-ctx.Done():
	case <-gen.failed:
	}
	stop()
	_ = nf.Close() // waits for the receive goroutine; the kernel drops queued packets
	cause := gen.failure()
	gen.close(cause)
	s.comp.flush()
	return cause
}

// receiveRecoverable reports receive errors that leave the queue usable:
// ENOBUFS means the kernel dropped packets it could not queue to us (no
// token was issued for them); timeouts and interrupts are transient.
func receiveRecoverable(err error) bool {
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}
