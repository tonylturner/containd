// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"errors"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

const (
	blockWorkerQueue = 256
	afterVerdictMax  = 4096
)

// inlineHooks receives capture's verdict completions and source events for
// one engine configuration. Capture calls them on its completion goroutine;
// Reconfigure moves the hooks together with the fresh capture manager.
type inlineHooks struct {
	active   func() bool
	source   func(capture.SourceEvent)
	after    *afterVerdict
	blocks   *worker
	sessions *sessionTable
	gate     *envelopeGate // the engine's envelope gate (bindGate)
	group    uint16        // this configuration's NFQUEUE group
	onError  func(error)
}

func newInlineHooks(onError func(error)) *inlineHooks {
	return &inlineHooks{
		after:   newAfterVerdict(afterVerdictMax),
		blocks:  newWorker(blockWorkerQueue),
		onError: onError,
	}
}

// Rejected resolutions are never submitted and receive no OnVerdict. Settle
// rejections are handled by their caller; returned Decision.Resolved rejections
// arrive here with the original generation-bearing token.
func (h *inlineHooks) onCaptureError(err error) {
	var rejected *capture.ResolutionRejectedError
	if errors.As(err, &rejected) && h.sessions != nil {
		h.sessions.onVerdict(rejected.Token, 0, rejected.Err)
	}
}

// onVerdict handles one verdict completion. Follow-up I/O registered for the
// token is queued now that its verdict submission has completed.
func (h *inlineHooks) onVerdict(tok capture.Token, v capture.Verdict, err error) {
	if job := h.after.take(tok); job != nil && !h.blocks.submit(job) {
		h.reportWorkerOverflow("block worker queue full")
	}
	if err != nil && !errors.Is(err, capture.ErrQueueClosed) && !errors.Is(err, capture.ErrTokenFlushed) {
		h.sessions.health.fault(faultVerdict, "verdict: "+err.Error())
		if h.onError != nil {
			h.onError(err)
		}
	}
	h.sessions.onVerdict(tok, v, err)
}

// onSource handles inline source state changes. A source that goes down
// aborts the enforce sessions; enforcement is healthy again only once the
// source reports ready.
func (h *inlineHooks) onSource(ev capture.SourceEvent) {
	if h.active != nil && !h.active() {
		return
	}
	if h.source != nil {
		h.source(ev)
	}
	// A queue closed by Stop (every Reconfigure) is not an error to log.
	if ev.Err != nil && !errors.Is(ev.Err, capture.ErrQueueClosed) && h.onError != nil {
		h.onError(ev.Err)
	}
	if ev.Ready {
		h.sessions.health.sourceReady()
		h.gate.own(h.group)
		return
	}
	// Close the envelope first: until this engine rebinds, nft drops
	// envelope traffic instead of queueing it.
	h.gate.own(0)
	reason := "queue down"
	if ev.Err != nil {
		reason = "queue down: " + ev.Err.Error()
	}
	h.sessions.health.fault(faultQueue, reason)
	h.sessions.onSourceDown(ev.Generation)
}

func (h *inlineHooks) reportWorkerOverflow(what string) {
	h.sessions.health.fault(faultWorker, what)
	if h.onError != nil {
		h.onError(errors.New("engine: " + what))
	}
}
