// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// drainWindow bounds the read after a refusal or an early response so
// the client sees the response instead of a reset.
const drainWindow = 500 * time.Millisecond

// conn is one client connection and its lazily dialled upstream.
type conn struct {
	srv        *Server
	id         string
	client     *peer
	clientAddr netip.AddrPort
	serverAddr netip.AddrPort
	txSeq      int
	// mu guards up and closed: the serve goroutine replaces the upstream
	// while Shutdown closes the connection from another goroutine.
	mu     sync.Mutex
	up     *upstream
	closed bool
}

// upstream is the origin connection. watch runs while it idles between
// transactions and reports an origin close before the next request.
type upstream struct {
	*peer
	used  bool
	watch *closeWatch
}

func newConn(s *Server, nc net.Conn, set *Settings) *conn {
	c := &conn{srv: s, id: s.nextConnID()}
	c.client = newPeer(nc, set.IdleTimeout)
	if ap, err := netip.ParseAddrPort(nc.RemoteAddr().String()); err == nil {
		c.clientAddr = unmap(ap)
	}
	return c
}

// serve runs transactions until the connection ends.
func (c *conn) serve() {
	defer c.closeAll()
	defer func() {
		if r := recover(); r != nil {
			c.srv.emit(c.connEvent(fmt.Sprintf("panic: %v\n%s", r, debug.Stack())))
		}
	}()
	dst, err := c.srv.OriginalDst(c.client.conn)
	if err != nil {
		c.srv.emit(c.connEvent("original destination: " + err.Error()))
		return
	}
	c.serverAddr = unmap(dst)
	for c.transaction() {
		if c.srv.ctx.Err() != nil {
			return
		}
		if c.up != nil {
			c.up.watch = watchClose(c.up.peer)
		}
	}
}

// transaction serves one request and reports whether the connection
// persists. The request head must complete within ObjectTimeout of its
// first byte; the idle timeout alone would let a dripped head live on.
func (c *conn) transaction() bool {
	c.client.active.Store(false)
	c.client.boundFromFirstByte(c.srv.settings.Load().ObjectTimeout)
	raw, err := readHead(c.client.r)
	c.client.setObjectDeadline(0)
	set := c.srv.settings.Load()
	c.client.idle = set.IdleTimeout
	switch {
	case errors.Is(err, errHeadTooLarge):
		c.unsupportedRequest(set, nil, raw, "request head over 64 KiB")
		return false
	case err != nil:
		return false
	}
	h, err := parseRequestHead(raw)
	if err != nil {
		c.unsupportedRequest(set, h, raw, err.Error())
		return false
	}
	c.txSeq++
	tx := &transaction{
		c:       c,
		set:     set,
		id:      c.id + "-" + strconv.Itoa(c.txSeq),
		start:   time.Now(),
		req:     h,
		reqHead: raw,
		ics:     set.ics(c.clientAddr, c.serverAddr),
	}
	return tx.run()
}

// unsupportedRequest applies the policy to a request head the gate cannot
// frame: a 400 under Block, a raw splice under PassUnscanned.
func (c *conn) unsupportedRequest(set *Settings, h *head, raw []byte, detail string) {
	res := gateResult(avscan.ReasonUnsupported, detail)
	ics := set.ics(c.clientAddr, c.serverAddr)
	action := set.decide(res, ics)
	ev := Event{
		ID: c.id + "-" + strconv.Itoa(c.txSeq+1), Direction: avscan.Upload,
		Client: c.clientAddr, Server: c.serverAddr, ICS: ics,
		Verdict: res.Verdict, Reason: res.Reason, Backend: res.Backend, Detail: detail, Action: action,
	}
	if h != nil {
		ev.Method, ev.Host, ev.Target = h.method, h.host, boundTarget(h.target)
	}
	c.srv.emit(ev)
	if action == avscan.Block {
		c.refuse(refusal(400, "Bad Request", "containd: unsupported HTTP request: "+detail, false), true)
		return
	}
	u, err := c.upstream(set)
	if err != nil {
		c.srv.emit(c.connEvent("dial: " + err.Error()))
		return
	}
	if _, err := u.Write(raw); err != nil {
		return
	}
	c.splice(u)
}

// splice relays raw bytes both ways until both directions end.
func (c *conn) splice(u *upstream) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		copyRaw(c.client, u.peer)
	}()
	copyRaw(u.peer, c.client)
	wg.Wait()
}

// copyRaw forwards src's buffered and future bytes to dst, then
// half-closes dst.
func copyRaw(dst, src *peer) {
	_, _ = io.Copy(dst, src.r)
	dst.closeWrite()
}

// upstream returns the origin connection, dialling when none is open.
func (c *conn) upstream(set *Settings) (*upstream, error) {
	if c.up != nil && c.up.watch != nil {
		closed := c.up.watch.stop()
		c.up.watch = nil
		if closed {
			c.closeUpstream()
		}
	}
	if c.up == nil {
		ctx, cancel := context.WithTimeout(c.srv.ctx, set.DialTimeout)
		defer cancel()
		nc, err := c.srv.dial(ctx, c.clientAddr, c.serverAddr)
		if err != nil {
			return nil, err
		}
		c.setUpstream(&upstream{peer: newPeer(nc, set.IdleTimeout)})
	}
	c.up.idle = set.IdleTimeout
	return c.up, nil
}

// setUpstream installs u; an upstream dialled after the connection was
// closed is closed at once so Shutdown never misses it.
func (c *conn) setUpstream(u *upstream) {
	c.mu.Lock()
	c.up = u
	closed := c.closed
	c.mu.Unlock()
	if closed && u != nil {
		u.close()
	}
}

func (c *conn) closeUpstream() {
	if c.up != nil {
		if c.up.watch != nil {
			c.up.watch.stop()
		}
		c.up.close()
		c.setUpstream(nil)
	}
}

// idle reports a connection awaiting its next request with no byte of it
// received; Shutdown closes such connections at once.
func (c *conn) idle() bool { return !c.client.active.Load() }

// closeAll closes both connections; safe to call concurrently with serve.
func (c *conn) closeAll() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	up := c.up
	c.mu.Unlock()
	c.client.close()
	if up != nil {
		up.close()
	}
}

// refuse writes a generated response and ends the connection. With drain
// the client side is half-closed and read until it stops or the drain
// window passes, so the response is read rather than reset.
func (c *conn) refuse(resp []byte, drain bool) {
	_, _ = c.client.Write(resp)
	if drain {
		c.client.closeWrite()
		c.client.drain(drainWindow)
	}
	c.closeAll()
}

// connEvent describes a connection the gate could not serve.
func (c *conn) connEvent(err string) Event {
	return Event{
		ID: c.id, Client: c.clientAddr, Server: c.serverAddr,
		Action: avscan.Block, Error: err,
	}
}

// refusal builds a generated response with Content-Length and
// Connection: close. headOnly omits the body for HEAD requests.
func refusal(status int, phrase, body string, headOnly bool) []byte {
	out := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, phrase, len(body))
	if !headOnly {
		out += body
	}
	return []byte(out)
}

// blockBody names containd and the signature or reason behind a refusal.
func blockBody(res avscan.Result) string {
	switch {
	case res.Signature != "":
		return "containd blocked this object: " + res.Signature + "\n"
	case res.Reason != "":
		return "containd refused this object: " + string(res.Reason) + "\n"
	}
	return "containd refused this object\n"
}

// unmap drops an IPv4-in-IPv6 mapping so endpoints compare as IPv4.
func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
