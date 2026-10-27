// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"errors"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// readResponse runs on its own goroutine for the lifetime of one upstream
// exchange: it relays interim responses, then holds or streams the final
// one. The sender is stopped once the final head is in; whether that
// truncated the request is the sender's finding, not this side's.
func (tx *transaction) readResponse(u *upstream, stop chan struct{}) respResult {
	c := tx.c
	interim := 0
	for {
		u.boundFromFirstByte(tx.set.ObjectTimeout)
		raw, err := readHead(u.r)
		u.setObjectDeadline(0)
		if err != nil {
			if errors.Is(err, errHeadTooLarge) {
				return tx.unsupportedResponse(u, nil, raw, "response head over 64 KiB", stop)
			}
			if len(raw) == 0 && interim == 0 && !isTimeout(err) {
				return respResult{retry: true}
			}
			c.srv.emit(c.connEvent("response head: " + err.Error()))
			return respResult{}
		}
		h, perr := parseResponseHead(raw, tx.req.method)
		if perr != nil {
			return tx.unsupportedResponse(u, h, raw, perr.Error(), stop)
		}
		if h.interim() {
			interim++
			if interim > maxInterim {
				return tx.unsupportedResponse(u, h, raw, "more than 16 interim responses", stop)
			}
			// The gate answered its own 100; an HTTP/1.0 client would take
			// any 1xx for the final response.
			if (h.status == 100 && tx.sent100) || tx.req.http10 {
				continue
			}
			if _, err := c.client.Write(raw); err != nil {
				return respResult{}
			}
			continue
		}
		tx.stopSend(u, stop)
		return respResult{persist: tx.deliverResponse(u, h)}
	}
}

// unsupportedResponse applies the policy to a response head the gate
// cannot frame: a 502 under Block, a raw splice under PassUnscanned.
func (tx *transaction) unsupportedResponse(u *upstream, h *head, raw []byte, detail string, stop chan struct{}) respResult {
	c := tx.c
	res := gateResult(avscan.ReasonUnsupported, detail)
	action := tx.set.decide(res, tx.ics)
	status := 0
	if h != nil {
		status = h.status
	}
	tx.emit(avscan.Download, res, action, 0, nil, false, status)
	if action == avscan.Block {
		tx.stopSend(u, stop)
		_, _ = c.client.Write(refusal(502, "Bad Gateway", "containd: unsupported HTTP response: "+detail, tx.headOnly()))
		return respResult{}
	}
	if _, err := c.client.Write(raw); err != nil {
		return respResult{}
	}
	close(tx.spliceCh)
	copyRaw(c.client, u.peer)
	return respResult{}
}

// deliverResponse relays, holds or refuses the final response h and
// reports whether the connection persists afterwards.
func (tx *transaction) deliverResponse(u *upstream, h *head) bool {
	c := tx.c
	persist := persistAfter(tx.req, h)
	if h.body == bodyNone {
		_, err := c.client.Write(h.raw)
		return err == nil && persist
	}
	body := bodySource{kind: h.body, rest: newBodyReader(h, u.r)}
	if !tx.set.ScanDownloads {
		return tx.writeResponse(h, body, nil) && persist
	}
	if h.partial() {
		// A part of an object is not the object: scanning it proves
		// nothing about the whole, so it is unsupported in every mode.
		res := gateResult(avscan.ReasonUnsupported, "partial object (206 or Content-Range)")
		if tx.set.decide(res, tx.ics) == avscan.Block {
			tx.refuseDownload(h, res, h.declaredLength(), nil, false)
			return false
		}
		return tx.writeResponse(h, body, &res) && persist
	}
	res, ok := tx.admit(h.declaredLength())
	if !ok {
		if tx.set.decide(res, tx.ics) == avscan.Block {
			tx.refuseDownload(h, res, h.declaredLength(), nil, false)
			return false
		}
		return tx.writeResponse(h, body, &res) && persist
	}
	defer c.srv.releaseObject()
	if tx.set.DownloadMode == DownloadStreamTail {
		return tx.streamDownload(u, h, body.rest) && persist
	}
	sp := newSpool(tx.set.SpoolDir, tx.set.MemoryThreshold)
	defer sp.close()
	outcome, excess, detail := tx.receive(sp, body.rest, u.peer, nil)
	switch outcome {
	case fillComplete:
		res, aborted := tx.scan(tx.object(avscan.Download, sp, h.raw), tx.downloadWatch())
		if aborted {
			tx.emit(avscan.Download, res, avscan.Block, sp.size, sp, false, h.status)
			return false
		}
		action := tx.set.decide(res, tx.ics)
		tx.emit(avscan.Download, res, action, sp.size, sp, false, h.status)
		if action == avscan.Block {
			tx.remember(res)
			_, _ = c.client.Write(refusal(403, "Forbidden", blockBody(res), tx.headOnly()))
			return false
		}
		return tx.writeResponse(h, bodySource{kind: h.body, held: sp}, nil) && persist
	case fillOversized, fillDisk:
		res := partialResult(outcome, detail)
		if tx.set.decide(res, tx.ics) == avscan.Block {
			tx.refuseDownload(h, res, max(sp.size, h.declaredLength()), sp, true)
			return false
		}
		return tx.writeResponse(h, bodySource{kind: h.body, held: sp, excess: excess, rest: body.rest}, &res) && persist
	default:
		tx.emit(avscan.Download, incompleteResult(outcome, detail), avscan.Block, sp.size, sp, true, h.status)
		return false
	}
}

// downloadWatch is the peer watched for a close while a download is
// scanned. The watcher reads the client socket: a sender still streaming
// the request body from it must have returned first, and one that did
// not finish the body left the client mid-request, whose bytes are no
// pipelined request and would overflow the watch; nothing is watched then.
func (tx *transaction) downloadWatch() *peer {
	if tx.streaming {
		<-tx.sendDone
		if tx.sendErr != nil {
			return nil
		}
	}
	return tx.c.client
}

// refuseDownload sends the client a 403 in place of the response. partial
// says whether sp holds only a prefix of the object.
func (tx *transaction) refuseDownload(h *head, res avscan.Result, size int64, sp *spool, partial bool) {
	tx.emit(avscan.Download, res, avscan.Block, size, sp, partial, h.status)
	_, _ = tx.c.client.Write(refusal(403, "Forbidden", blockBody(res), tx.headOnly()))
}

// writeResponse sends the head as received and the body in its original
// framing. pass, when set, is emitted once the body has been forwarded.
// A body that fails part way, on either side, resets both connections:
// the client holds a prefix that must not pass for the object, and with
// close-delimited framing a FIN would complete it.
func (tx *transaction) writeResponse(h *head, src bodySource, pass *avscan.Result) bool {
	c := tx.c
	if _, err := c.client.Write(h.raw); err != nil {
		return false
	}
	sent, err := writeBody(newBodyWriter(c.client, src.kind), src, nil)
	if pass != nil {
		tx.emit(avscan.Download, *pass, avscan.PassUnscanned, sent, src.held, true, h.status)
	}
	if err != nil {
		c.resetAll()
		return false
	}
	return true
}
