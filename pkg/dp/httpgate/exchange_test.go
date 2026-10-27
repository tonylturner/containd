// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// latchConn is an origin connection whose first Write hands its bytes to
// the origin and then does not return until release is closed. It holds
// the request sender inside its Write while the origin already answers,
// the scheduling the response reader must not depend on.
type latchConn struct {
	net.Conn
	once    sync.Once
	release <-chan struct{}
}

func (c *latchConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.once.Do(func() { <-c.release })
	return n, err
}

// latchedDial installs a Dial hook on o that latches the first write of
// every upstream connection. Call release before the gate shuts down.
func latchedDial(o *origin) (release func()) {
	ch := make(chan struct{})
	o.dial = func(_ context.Context, _, server netip.AddrPort) (net.Conn, error) {
		nc, err := net.Dial("tcp", server.String())
		if err != nil {
			return nil, err
		}
		return &latchConn{Conn: nc, release: ch}, nil
	}
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// An origin that answers a GET before the sender's Write has returned is
// not answering early: the connection stays usable for the next request.
func TestResponseBeforeSendReturnsKeepsConnection(t *testing.T) {
	log := &bodyLog{}
	o := pathOrigin(t, log)
	release := latchedDial(o)
	defer release()
	g := startGate(t, o, nil)
	c := g.client()
	c.write(getRequest("/first", ""))
	resp, rb := c.response("GET")
	if resp.StatusCode != 200 || string(rb) != "path=/first" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	expectEvent(t, g.events.next(t), avscan.Download, avscan.Clean, "", avscan.Deliver)
	release()
	c.write(getRequest("/second", ""))
	resp, rb = c.response("GET")
	if resp.StatusCode != 200 || string(rb) != "path=/second" {
		t.Fatalf("second request on the kept connection: status %d body %q", resp.StatusCode, rb)
	}
	if o.rec.connections() != 1 {
		t.Fatalf("origin connections %d, want the first one reused", o.rec.connections())
	}
}

// The same scheduling must not blind the download hold to the client:
// a client that half-closes during the scan still aborts it.
func TestResponseBeforeSendReturnsWatchesClient(t *testing.T) {
	body := append(pattern(4096, 110), []byte(infectedMarker)...)
	o := rawOrigin(t, func(c net.Conn, _ int) {
		if _, _, err := readRequestHead(c); err != nil {
			return
		}
		_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
		_, _ = c.Write(body)
	})
	release := latchedDial(o)
	defer release()
	g := startGate(t, o, func(s *Settings) { s.FailPolicy = avscan.FailOpen; s.ScanTimeout = time.Minute })
	releaseScan := g.scanner.holdScans()
	defer releaseScan()
	c := g.client()
	c.write(getRequest("/malware", ""))
	g.scanner.waitScanStarted(t)
	if err := c.conn.(*recConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Download, avscan.Unscanned, avscan.ReasonAborted, avscan.Block)
	if ev.Detail != "client closed before the verdict" || ev.Status != 200 {
		t.Fatalf("event %+v", ev)
	}
	release()
	c.expectClosed()
	if n := len(c.rec.bytes()); n != 0 {
		t.Fatalf("client received %d bytes after half-closing under fail-open", n)
	}
}

// A true early response: the origin answers a held upload at its head
// and stops reading. The sender, blocked on an origin that no longer
// reads, must give up within the drain window, not the idle timeout, so
// both connections close promptly after the response.
func TestEarlyResponseToHeldUploadClosesPromptly(t *testing.T) {
	check := make(chan struct{})
	originDone := make(chan error, 1)
	o := rawOrigin(t, func(c net.Conn, _ int) {
		if _, _, err := readRequestHead(c); err != nil {
			originDone <- err
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 3\r\n\r\nbig")
		// Read nothing more, so the gate's writes block once the socket
		// buffers are full; drain only when asked to check for the close.
		<-check
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := io.Copy(io.Discard, c)
		originDone <- err
	})
	g := startGate(t, o, func(s *Settings) { s.IdleTimeout = time.Minute; s.MaxObjectBytes = 32 << 20 })
	c := g.client()
	body := pattern(24<<20, 111)
	c.write(requestCL("POST", "/big", "", body))
	resp, rb := c.response("POST")
	if resp.StatusCode != 413 || string(rb) != "big" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	c.expectClosed()
	close(check)
	select {
	case err := <-originDone:
		if err != nil && isTimeout(err) {
			t.Fatal("origin connection left open after its early response")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("origin did not finish draining")
	}
	expectEvent(t, g.events.next(t), avscan.Upload, avscan.Clean, "", avscan.Deliver)
	expectEvent(t, g.events.next(t), avscan.Download, avscan.Clean, "", avscan.Deliver)
}

// When the origin answers while the request body still streams from the
// client, the body bytes the client keeps sending during the response
// hold are not a pipelined request: they must not abort the scan.
func TestTruncatedUploadBytesDuringResponseHoldIgnored(t *testing.T) {
	o := rawOrigin(t, func(c net.Conn, _ int) {
		if _, _, err := readRequestHead(c); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 3\r\n\r\nbig")
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
		_, _ = io.Copy(io.Discard, c)
	})
	g := startGate(t, o, func(s *Settings) { s.ScanUploads = false; s.ScanTimeout = time.Minute })
	release := g.scanner.holdScans()
	defer release()
	c := g.client()
	head := requestCL("POST", "/slow", "", nil)
	c.write(head[:len(head)-len("Content-Length: 0\r\n\r\n")])
	c.write([]byte(fmt.Sprintf("Content-Length: %d\r\n\r\n", 1<<20)))
	c.write(pattern(1024, 112))
	g.scanner.waitScanStarted(t)
	written := make(chan struct{})
	go func() {
		defer close(written)
		_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.conn.Write(bytes.Repeat([]byte("b"), pipelineCap+4096))
	}()
	g.events.expectNone(t, 200*time.Millisecond)
	release()
	resp, rb := c.response("POST")
	if resp.StatusCode != 413 || string(rb) != "big" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	expectEvent(t, g.events.next(t), avscan.Download, avscan.Clean, "", avscan.Deliver)
	c.expectClosed()
	<-written
}
