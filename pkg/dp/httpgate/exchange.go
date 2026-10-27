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
type bodySource struct {
	kind   bodyKind
	held   *spool
	excess []byte
	rest   io.Reader
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
// reports whether the connection persists.
func (tx *transaction) exchange(body bodySource, pass *avscan.Result) bool {
	c := tx.c
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
		tx.sendDone.Store(false)
		tx.spliceCh = make(chan struct{})
		done := make(chan respResult, 1)
		go func() { done <- tx.readResponse(u, stop) }()

		sent, sendErr := tx.send(u, body, stop)
		if pass != nil {
			tx.emit(avscan.Upload, *pass, avscan.PassUnscanned, sent, body.held, 0)
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

// send writes the request head and body upstream. When stop closes while
// the body is still streaming from the client, the rest of it is drained
// briefly so the client can read the early response.
func (tx *transaction) send(u *upstream, body bodySource, stop <-chan struct{}) (int64, error) {
	if _, err := u.Write(tx.reqHead); err != nil {
		return 0, err
	}
	var sent int64
	if body.kind != bodyNone {
		var err error
		sent, err = writeBody(newBodyWriter(u, body.kind), body, stop)
		if err != nil {
			if errors.Is(err, errStopped) && body.rest != nil {
				tx.c.client.bound(drainWindow)
				_, _ = io.CopyN(io.Discard, body.rest, drainLimit)
				tx.c.client.setObjectDeadline(0)
			}
			return sent, err
		}
	}
	tx.sendDone.Store(true)
	return sent, nil
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
