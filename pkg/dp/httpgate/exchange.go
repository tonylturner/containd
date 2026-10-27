// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"errors"
	"io"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// bodySource is a message body as the gate forwards it: an optional held
// prefix, bytes read past the hold cap, and the still-unread remainder.
// release, when set, frees the held prefix and its object slot once the
// body has been sent.
type bodySource struct {
	kind    bodyKind
	held    *spool
	excess  []byte
	rest    io.Reader
	release func()
}

// writeBody frames src on w in order and returns the bytes written.
func writeBody(w bodyWriter, src bodySource, stop <-chan struct{}) (int64, error) {
	var total int64
	if src.held != nil {
		n, err := copyBody(w, src.held.reader(), stop)
		total += n
		if err != nil {
			return total, err
		}
	}
	if len(src.excess) > 0 {
		if closed(stop) {
			return total, errStopped
		}
		if _, err := w.Write(src.excess); err != nil {
			return total, err
		}
		total += int64(len(src.excess))
	}
	if src.rest != nil {
		n, err := copyBody(w, src.rest, stop)
		total += n
		if err != nil {
			return total, err
		}
	}
	// EOF completes a length body, but a chunked body still needs its
	// terminator on the wire. A stop before that write truncates it.
	if src.kind == bodyChunked && closed(stop) {
		return total, errStopped
	}
	return total, w.finish()
}

// respResult is what the response side reports back to exchange.
type respResult struct {
	persist bool
	// retry: the reused origin connection closed before sending a byte.
	retry bool
}

// exchange sends the request upstream while reading the response
// concurrently. pass, when set, is the Unscanned result of an unheld
// body whose event is emitted once the body has been forwarded. It
// reports whether the connection persists: never after a send the
// response side stopped, since the origin saw a truncated request.
func (tx *transaction) exchange(body bodySource, pass *avscan.Result) bool {
	c := tx.c
	tx.streaming = body.rest != nil
	for attempt := 0; ; attempt++ {
		u, err := c.upstream(tx.set)
		if err != nil {
			c.srv.emit(c.connEvent("dial: " + err.Error()))
			c.refuse(refusal(502, "Bad Gateway", "containd: upstream connection failed\n", tx.headOnly()), true)
			return false
		}
		reused := u.used
		u.used = true
		stop := make(chan struct{})
		tx.sendDone, tx.sendErr = make(chan struct{}), nil
		tx.spliceCh = make(chan struct{})
		done := make(chan respResult, 1)
		go func() {
			// A recovered panic leaves r zero: the exchange closes both.
			var r respResult
			c.guard(func() { r = tx.readResponse(u, stop) })
			done <- r
		}()

		sent, sendErr := tx.send(u, body, stop)
		if pass != nil {
			tx.emit(avscan.Upload, *pass, avscan.PassUnscanned, sent, body.held, true, 0)
		}
		if body.release != nil {
			body.release()
		}
		if sendErr != nil && !errors.Is(sendErr, errStopped) {
			u.close()
		}
		var r respResult
		select {
		case r = <-done:
		case <-tx.spliceCh:
			if sendErr == nil {
				copyRaw(u.peer, c.client)
			}
			r = <-done
		}
		// Bounds stopSend set on peers the sender had already left are
		// stale now that both sides have returned.
		c.client.setObjectDeadline(0)
		u.boundWrite(0)
		switch {
		case r.retry && reused && attempt == 0 && body.kind == bodyNone && idempotent(tx.req.method):
			c.closeUpstream()
			continue
		case sendErr != nil && !errors.Is(sendErr, errStopped) && !closed(stop):
			c.srv.emit(c.connEvent("request: " + sendErr.Error()))
		case r.retry:
			c.srv.emit(c.connEvent("origin closed before responding"))
		}
		if sendErr != nil || !r.persist {
			c.closeAll()
			return false
		}
		return true
	}
}

// send writes the request head and body upstream and records its outcome
// for the response side. A send that stop ended is truncated whichever
// call noticed first: the stop check, a bounded client read or a bounded
// origin write. When the body was still streaming from the client, the
// rest of it is drained for the drain window so the client can read the
// response.
func (tx *transaction) send(u *upstream, body bodySource, stop <-chan struct{}) (sent int64, err error) {
	defer func() {
		tx.sendErr = err
		close(tx.sendDone)
	}()
	if _, err = u.Write(tx.reqHead); err == nil && body.kind != bodyNone {
		sent, err = writeBody(newBodyWriter(u, body.kind), body, stop)
	}
	if err == nil {
		return sent, nil
	}
	if closed(stop) {
		err = errStopped
	}
	if errors.Is(err, errStopped) && body.rest != nil {
		tx.c.client.bound(drainWindow)
		_, _ = io.Copy(io.Discard, body.rest)
	}
	return sent, err
}

// stopSend tells the sender that the final response head is in: whatever
// is left of the request is not forwarded. The sender notices at its
// next stop check; one blocked reading the body from the client or
// writing to an origin that stopped reading is bounded so it returns
// within the drain window. A sender that has already finished is not
// affected, and exchange clears the bounds once both sides returned.
func (tx *transaction) stopSend(u *upstream, stop chan struct{}) {
	close(stop)
	if tx.streaming {
		tx.c.client.bound(drainWindow)
	}
	u.boundWrite(drainWindow)
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// idempotent lists the methods a request may be resent for after the
// origin closed an idle connection.
func idempotent(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return false
}

// persistAfter reports whether the connection stays open after resp.
func persistAfter(req, resp *head) bool {
	switch {
	case req.connClose, resp.connClose:
		return false
	case req.http10 && !req.keepAlive:
		return false
	case resp.http10 && !resp.keepAlive:
		return false
	case resp.body == bodyUntilClose:
		return false
	}
	return true
}
