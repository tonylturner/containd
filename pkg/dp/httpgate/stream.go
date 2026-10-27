// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"io"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// tailStreamer forwards a download body to the client as the spool
// grows, always keeping the last streamTailBytes back. It reads the
// bytes to forward back out of the spool, which already holds them for
// the scanner, so no second buffer tracks the window.
type tailStreamer struct {
	sp   *spool
	w    bodyWriter
	sent int64
	buf  []byte
}

// forward relays the spool bytes before the tail that are not sent yet.
func (t *tailStreamer) forward() error { return t.forwardTo(t.sp.size - streamTailBytes) }

// flush relays everything the spool holds, the tail included.
func (t *tailStreamer) flush() error { return t.forwardTo(t.sp.size) }

func (t *tailStreamer) forwardTo(end int64) error {
	if t.buf == nil {
		t.buf = make([]byte, copyBufSize)
	}
	for t.sent < end {
		n := min(end-t.sent, int64(len(t.buf)))
		if _, err := t.sp.ReadAt(t.buf[:n], t.sent); err != nil {
			return err
		}
		if _, err := t.w.Write(t.buf[:n]); err != nil {
			return err
		}
		t.sent += n
	}
	return nil
}

// streamDownload serves a response body in stream_tail mode: the head and
// every body byte but the last streamTailBytes reach the client while the
// spool fills, then the verdict decides whether the tail follows. Any
// other ending resets both connections: the client holds a prefix that
// must not pass for the object, and with close-delimited framing a FIN
// would complete it. It reports whether the whole body reached the
// client; the caller holds the object slot.
func (tx *transaction) streamDownload(u *upstream, h *head, body io.Reader) bool {
	c := tx.c
	sp := newSpool(tx.set.SpoolDir, tx.set.MemoryThreshold)
	defer sp.close()
	if _, err := c.client.Write(h.raw); err != nil {
		return false
	}
	st := &tailStreamer{sp: sp, w: newBodyWriter(c.client, h.body)}
	outcome, excess, detail := tx.receive(sp, body, u.peer, st.forward)
	tx.streamed = st.sent
	switch outcome {
	case fillComplete:
		res, aborted := tx.scan(tx.object(avscan.Download, sp, h.raw), tx.downloadWatch())
		if aborted {
			tx.emit(avscan.Download, res, avscan.Block, sp.size, sp, false, h.status)
			c.resetAll()
			return false
		}
		action := tx.set.decide(res, tx.ics)
		tx.emit(avscan.Download, res, action, sp.size, sp, false, h.status)
		if action == avscan.Block {
			tx.remember(res)
			c.resetAll()
			return false
		}
		_, ok := tx.finishStream(st, nil, nil)
		return ok
	case fillOversized, fillDisk:
		res := partialResult(outcome, detail)
		if tx.set.decide(res, tx.ics) == avscan.Block {
			tx.emit(avscan.Download, res, avscan.Block, max(sp.size, h.declaredLength()), sp, true, h.status)
			c.resetAll()
			return false
		}
		sent, ok := tx.finishStream(st, excess, body)
		tx.emit(avscan.Download, res, avscan.PassUnscanned, sent, sp, true, h.status)
		return ok
	case fillForward:
		tx.emit(avscan.Download, gateResult(avscan.ReasonAborted, detail), avscan.Block, sp.size, sp, true, h.status)
		c.resetAll()
		return false
	default:
		tx.emit(avscan.Download, incompleteResult(outcome, detail), avscan.Block, sp.size, sp, true, h.status)
		c.resetAll()
		return false
	}
}

// finishStream delivers the rest of a streamed body: the held tail, the
// bytes read past the hold cap and the unread remainder, then the framing
// terminator. It returns the body bytes the client received in all and
// whether the body completed; a failure resets both connections.
func (tx *transaction) finishStream(st *tailStreamer, excess []byte, rest io.Reader) (int64, bool) {
	err := st.flush()
	sent := st.sent
	if err == nil && len(excess) > 0 {
		_, err = st.w.Write(excess)
		sent += int64(len(excess))
	}
	if err == nil && rest != nil {
		var n int64
		n, err = copyBody(st.w, rest, nil)
		sent += n
	}
	if err == nil {
		err = st.w.finish()
	}
	if err != nil {
		tx.c.resetAll()
		return sent, false
	}
	return sent, true
}
