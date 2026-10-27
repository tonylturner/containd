// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// A client that half-closes while its infected upload is being scanned
// ends the transaction: under fail-open the origin still gets no byte.
func TestClientHalfCloseDuringScanAbortsUpload(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.FailPolicy = avscan.FailOpen; s.ScanTimeout = time.Minute })
	release := g.scanner.holdScans()
	defer release()
	body := append(pattern(4096, 101), []byte(infectedMarker)...)
	c := g.client()
	c.write(requestCL("POST", "/malware", "", body))
	g.scanner.waitScanStarted(t)
	if err := c.conn.(*recConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonTimeout, avscan.Block)
	if ev.Detail != "client closed before the verdict" || ev.Size != int64(len(body)) || ev.SHA256 != sha256hex(body) || ev.SHA256Partial {
		t.Fatalf("event %+v", ev)
	}
	c.expectClosed()
	if n := len(c.rec.bytes()); n != 0 {
		t.Fatalf("client received %d bytes for an aborted transaction", n)
	}
	if o.rec.connections() != 0 || len(o.rec.bytes()) != 0 {
		t.Fatalf("origin got %d connections, %d bytes after the client half-closed under fail-open", o.rec.connections(), len(o.rec.bytes()))
	}
	if calls := g.scanner.scanCalls(); len(calls) != 1 || !errors.Is(calls[0].ctxErr, context.Canceled) {
		t.Fatalf("scan calls %+v", calls)
	}
}

// The same for a download: the client that half-closes while the
// infected response is being scanned receives no byte of it.
func TestClientHalfCloseDuringScanAbortsDownload(t *testing.T) {
	body := append(pattern(4096, 102), []byte(infectedMarker)...)
	originDone := make(chan error, 1)
	o := rawOrigin(t, func(c net.Conn, _ int) {
		if _, _, err := readRequestHead(c); err != nil {
			originDone <- err
			return
		}
		_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
		_, _ = c.Write(body)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := c.Read(make([]byte, 1))
		originDone <- err
	})
	g := startGate(t, o, func(s *Settings) { s.FailPolicy = avscan.FailOpen; s.ScanTimeout = time.Minute })
	release := g.scanner.holdScans()
	defer release()
	c := g.client()
	c.write(getRequest("/malware", ""))
	g.scanner.waitScanStarted(t)
	if err := c.conn.(*recConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Download, avscan.Unscanned, avscan.ReasonTimeout, avscan.Block)
	if ev.Detail != "client closed before the verdict" || ev.Status != 200 || ev.SHA256 != sha256hex(body) || ev.SHA256Partial {
		t.Fatalf("event %+v", ev)
	}
	c.expectClosed()
	if raw := c.rec.bytes(); len(raw) != 0 {
		t.Fatalf("client received %d bytes after half-closing under fail-open", len(raw))
	}
	select {
	case err := <-originDone:
		if err == nil || isTimeout(err) {
			t.Fatalf("origin connection not closed by the gate: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin connection left open")
	}
}

// A request pipelined behind the held upload must not blind the gate to
// the client closing during the scan.
func TestPipelinedCloseDuringScanIsObserved(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.ScanDownloads = false; s.ScanTimeout = time.Minute })
	release := g.scanner.holdScans()
	defer release()
	c := g.client()
	c.write(append(requestCL("POST", "/held", "", pattern(1000, 103)), getRequest("/next", "")...))
	g.scanner.waitScanStarted(t)
	c.conn.Close()
	start := time.Now()
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonTimeout, avscan.Block)
	if ev.Detail != "client closed before the verdict" || time.Since(start) > 2*time.Second {
		t.Fatalf("event %+v after %v", ev, time.Since(start))
	}
	if calls := g.scanner.scanCalls(); len(calls) != 1 || !errors.Is(calls[0].ctxErr, context.Canceled) {
		t.Fatalf("scan calls %+v", calls)
	}
	if o.rec.connections() != 0 {
		t.Fatal("origin dialled after the client left")
	}
}

// Pipelined bytes are kept for the next transaction up to a bound; past
// it the connection ends rather than the watch.
func TestPipelinedBytesDuringScan(t *testing.T) {
	t.Run("kept", func(t *testing.T) {
		log := &bodyLog{}
		o := pathOrigin(t, log)
		g := startGate(t, o, func(s *Settings) { s.ScanDownloads = false })
		release := g.scanner.holdScans()
		c := g.client()
		c.write(requestCL("POST", "/first", "", pattern(1000, 104)))
		g.scanner.waitScanStarted(t)
		// Sent while the gate is only watching the client.
		c.write(getRequest("/second", "X-Pad: "+strings.Repeat("a", 20<<10)+"\r\n"))
		time.Sleep(50 * time.Millisecond)
		release()
		for _, want := range []string{"path=/first", "path=/second"} {
			resp, rb := c.response("GET")
			if resp.StatusCode != 200 || string(rb) != want {
				t.Fatalf("status %d body %q, want %q", resp.StatusCode, rb, want)
			}
		}
		if entries := log.list(); len(entries) != 2 || entries[1].header.Get("X-Pad") != strings.Repeat("a", 20<<10) {
			t.Fatalf("origin requests %d", len(entries))
		}
	})
	t.Run("overflow", func(t *testing.T) {
		log := &bodyLog{}
		o := echoOrigin(t, log)
		g := startGate(t, o, func(s *Settings) { s.ScanDownloads = false; s.ScanTimeout = time.Minute })
		release := g.scanner.holdScans()
		defer release()
		c := g.client()
		c.write(requestCL("POST", "/first", "", pattern(1000, 105)))
		g.scanner.waitScanStarted(t)
		go func() {
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, _ = c.conn.Write(bytes.Repeat([]byte("G"), pipelineCap+1))
		}()
		ev := g.events.next(t)
		expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonTimeout, avscan.Block)
		if !strings.Contains(ev.Detail, "pipelined before the verdict") {
			t.Fatalf("event %+v", ev)
		}
		c.expectClosed()
		if o.rec.connections() != 0 {
			t.Fatal("origin dialled after the pipeline overflowed")
		}
	})
}
