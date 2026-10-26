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
	after   *afterVerdict
	blocks  *worker
	iec     *iecTable
	gate    *envelopeGate // the engine's envelope gate (bindGate)
	group   uint16        // this configuration's NFQUEUE group
	onError func(error)
}

func newInlineHooks(onError func(error)) *inlineHooks {
	return &inlineHooks{
		after:   newAfterVerdict(afterVerdictMax),
		blocks:  newWorker(blockWorkerQueue),
		onError: onError,
	}
}

// onVerdict handles one verdict completion. Follow-up I/O registered for the
// token (a dynamic block) is queued now that its drop is submitted.
func (h *inlineHooks) onVerdict(tok capture.Token, _ capture.Verdict, err error) {
	if job := h.after.take(tok); job != nil && !h.blocks.submit(job) {
		h.reportWorkerOverflow("block worker queue full")
	}
	if err != nil && !errors.Is(err, capture.ErrQueueClosed) {
		h.iec.health.fault(faultVerdict, "verdict: "+err.Error())
		if h.onError != nil {
			h.onError(err)
		}
	}
	h.iec.onVerdict(tok, err)
}

// onSource handles inline source state changes. A source that goes down
// aborts the enforce sessions; enforcement is healthy again only once the
// source reports ready (contracts K6).
func (h *inlineHooks) onSource(ev capture.SourceEvent) {
	// A queue closed by Stop (every Reconfigure) is not an error to log.
	if ev.Err != nil && !errors.Is(ev.Err, capture.ErrQueueClosed) && h.onError != nil {
		h.onError(ev.Err)
	}
	if ev.Ready {
		h.iec.health.sourceReady()
		h.gate.own(h.group)
		return
	}
	// Close the envelope first: until this engine rebinds, nft drops
	// envelope traffic instead of queueing it (contracts K8).
	h.gate.own(0)
	reason := "queue down"
	if ev.Err != nil {
		reason = "queue down: " + ev.Err.Error()
	}
	h.iec.health.fault(faultQueue, reason)
	h.iec.onSourceDown()
}

func (h *inlineHooks) reportWorkerOverflow(what string) {
	h.iec.health.fault(faultWorker, what)
	if h.onError != nil {
		h.onError(errors.New("engine: " + what))
	}
}
