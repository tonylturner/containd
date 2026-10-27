// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// transaction is one request and its response on a connection. It keeps
// the Settings snapshot taken when the request head was parsed.
type transaction struct {
	c     *conn
	set   *Settings
	id    string
	start time.Time
	req   *head
	// reqHead is the head sent upstream: the raw bytes, minus Expect when
	// the gate answered it.
	reqHead []byte
	ics     bool
	sent100 bool
	// sendDone is set once the whole request has been written upstream;
	// a final response before that is early.
	sendDone atomic.Bool
	// spliceCh is closed when the response side switched to a raw splice.
	spliceCh chan struct{}
}

// run serves the transaction and reports whether the connection persists.
func (tx *transaction) run() bool {
	h := tx.req
	if h.hasExpect && h.expect != "100-continue" {
		res := gateResult(avscan.ReasonUnsupported, "Expect: "+h.expect)
		tx.emit(avscan.Upload, res, avscan.Block, h.declaredLength(), nil, false, 0)
		tx.c.refuse(refusal(417, "Expectation Failed", "containd: unsupported Expect\n", tx.headOnly()), true)
		return false
	}
	body := bodySource{kind: h.body, rest: newBodyReader(h, tx.c.client.r)}
	if h.body == bodyNone || !tx.set.ScanUploads {
		return tx.exchange(body, nil)
	}
	res, ok := tx.admit(h.declaredLength())
	if !ok {
		if tx.set.decide(res, tx.ics) == avscan.Block {
			tx.refuseUpload(res, h.declaredLength(), nil, false)
			return false
		}
		return tx.exchange(body, &res)
	}
	return tx.holdUpload(body.rest)
}

// holdUpload spools the request body, has it scanned and acts on the
// decision. It owns the object slot admit took: the slot and the spool
// are released as soon as the body has been sent upstream, so the
// response that follows can be held with the same slot.
func (tx *transaction) holdUpload(body io.Reader) bool {
	h := tx.req
	if h.hasExpect {
		if _, err := tx.c.client.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n")); err != nil {
			tx.c.srv.releaseObject()
			return false
		}
		tx.sent100 = true
		tx.reqHead = h.without("Expect")
	}
	sp := newSpool(tx.set.SpoolDir, tx.set.MemoryThreshold)
	var once sync.Once
	release := func() {
		once.Do(func() {
			sp.close()
			tx.c.srv.releaseObject()
		})
	}
	defer release()
	outcome, excess, detail := tx.receive(sp, body, tx.c.client)
	switch outcome {
	case fillComplete:
		res := tx.scan(tx.object(avscan.Upload, sp, nil), tx.c.client)
		action := tx.set.decide(res, tx.ics)
		tx.emit(avscan.Upload, res, action, sp.size, sp, false, 0)
		if action == avscan.Block {
			tx.c.refuse(refusal(403, "Forbidden", blockBody(res), tx.headOnly()), true)
			return false
		}
		return tx.exchange(bodySource{kind: h.body, held: sp, release: release}, nil)
	case fillOversized, fillDisk:
		res := partialResult(outcome, detail)
		if tx.set.decide(res, tx.ics) == avscan.Block {
			tx.refuseUpload(res, max(sp.size, h.declaredLength()), sp, true)
			return false
		}
		return tx.exchange(bodySource{kind: h.body, held: sp, excess: excess, rest: body, release: release}, &res)
	default:
		tx.emit(avscan.Upload, incompleteResult(outcome, detail), avscan.Block, sp.size, sp, true, 0)
		tx.c.closeAll()
		return false
	}
}

// refuseUpload answers 403 before the origin has seen a byte. partial
// says whether sp holds only a prefix of the object.
func (tx *transaction) refuseUpload(res avscan.Result, size int64, sp *spool, partial bool) {
	tx.emit(avscan.Upload, res, avscan.Block, size, sp, partial, 0)
	tx.c.refuse(refusal(403, "Forbidden", blockBody(res), tx.headOnly()), true)
}

// admit runs the checks that precede holding a body: readiness, the
// object limit, then the declared length. On success one object slot is
// held.
func (tx *transaction) admit(declared int64) (avscan.Result, bool) {
	if ok, why := tx.c.srv.Scanner.Ready(); !ok {
		return gateResult(avscan.ReasonNotReady, why), false
	}
	if !tx.c.srv.acquireObject(tx.set.MaxConcurrentObjects) {
		return gateResult(avscan.ReasonBusy, "object limit reached"), false
	}
	if declared > tx.set.MaxObjectBytes {
		tx.c.srv.releaseObject()
		return gateResult(avscan.ReasonOversized,
			fmt.Sprintf("Content-Length %d exceeds %d bytes", declared, tx.set.MaxObjectBytes)), false
	}
	return avscan.Result{}, true
}

// receive spools body from p under the object deadline and describes how
// it ended.
func (tx *transaction) receive(sp *spool, body io.Reader, p *peer) (fillOutcome, []byte, string) {
	p.setObjectDeadline(tx.set.ObjectTimeout)
	outcome, excess, err := sp.fill(body, tx.set.MaxObjectBytes)
	var detail string
	switch outcome {
	case fillTimeout:
		detail = "idle timeout while receiving body"
		if p.objectDeadlineHit() {
			detail = "object deadline exceeded"
		}
	case fillFraming, fillDisk:
		detail = err.Error()
	case fillOversized:
		detail = fmt.Sprintf("body exceeds %d bytes", tx.set.MaxObjectBytes)
	}
	p.setObjectDeadline(0)
	return outcome, excess, detail
}

// partialResult is the gate result for a body held only in part.
func partialResult(outcome fillOutcome, detail string) avscan.Result {
	if outcome == fillDisk {
		return gateResult(avscan.ReasonBusy, detail)
	}
	return gateResult(avscan.ReasonOversized, detail)
}

// incompleteResult is the gate result for a body that cannot complete.
func incompleteResult(outcome fillOutcome, detail string) avscan.Result {
	if outcome == fillTimeout {
		return gateResult(avscan.ReasonTimeout, detail)
	}
	return gateResult(avscan.ReasonUnsupported, detail)
}

// scan classifies obj. The context ends with the scan timeout, Shutdown,
// or the watched peer closing.
func (tx *transaction) scan(obj avscan.Object, watch *peer) avscan.Result {
	ctx, cancel := context.WithTimeout(tx.c.srv.ctx, tx.set.ScanTimeout)
	if watch != nil {
		w := watchClose(watch, tx.c.guard)
		defer w.stop()
		go func() {
			select {
			case <-w.closed:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	defer cancel()
	res := tx.c.srv.Scanner.Scan(ctx, obj)
	switch res.Verdict {
	case avscan.Clean, avscan.Infected, avscan.Unscanned:
	default:
		res = avscan.Result{
			Verdict: avscan.Unscanned, Reason: avscan.ReasonScannerError, Backend: res.Backend,
			Detail: fmt.Sprintf("scanner returned verdict %q", res.Verdict),
		}
	}
	return res
}

// object describes the held body for the scanner.
func (tx *transaction) object(dir avscan.Direction, sp *spool, respHead []byte) avscan.Object {
	return avscan.Object{
		ID:           tx.id,
		Direction:    dir,
		Client:       tx.c.clientAddr,
		Server:       tx.c.serverAddr,
		RequestHead:  tx.reqHead,
		ResponseHead: respHead,
		Body:         sp,
		Size:         sp.size,
		SHA256:       sp.sum(),
		ICS:          tx.ics,
	}
}

// emit records one object decision. sp holds the hashed bytes, nil when
// nothing was held; partial says explicitly that those bytes are only a
// prefix of the object (oversized, disk error, incomplete, streamed on).
func (tx *transaction) emit(dir avscan.Direction, res avscan.Result, action avscan.Action, size int64, sp *spool, partial bool, status int) {
	ev := Event{
		ID: tx.id, Direction: dir, Client: tx.c.clientAddr, Server: tx.c.serverAddr, ICS: tx.ics,
		Method: tx.req.method, Host: tx.req.host, Target: boundTarget(tx.req.target), Status: status,
		Size: size, Verdict: res.Verdict, Reason: res.Reason, Signature: res.Signature,
		Backend: res.Backend, Detail: res.Detail, Action: action, Duration: time.Since(tx.start),
	}
	if sp != nil && sp.size > 0 {
		ev.SHA256, ev.SHA256Partial = sp.sum(), partial
	} else {
		ev.SHA256Partial = partial || size > 0
	}
	tx.c.srv.emit(ev)
}

func (tx *transaction) headOnly() bool { return tx.req.method == "HEAD" }
