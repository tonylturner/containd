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
	if err != nil && !errors.Is(err, capture.ErrQueueClosed) && h.onError != nil {
		h.onError(err)
	}
}

// onSource handles inline source state changes.
func (h *inlineHooks) onSource(ev capture.SourceEvent) {
	if ev.Err != nil && h.onError != nil {
		h.onError(ev.Err)
	}
}

func (h *inlineHooks) reportWorkerOverflow(what string) {
	if h.onError != nil {
		h.onError(errors.New("engine: " + what))
	}
}
