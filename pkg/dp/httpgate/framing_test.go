// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// badChunkedRequest has one good chunk and then an invalid chunk-size line.
func badChunkedRequest() []byte {
	return []byte("POST /bad HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nzz\r\n")
}

func TestMidBodyChunkErrorClosesBoth(t *testing.T) {
	forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
		t.Run("held", func(t *testing.T) {
			log := &bodyLog{}
			o := echoOrigin(t, log)
			g := startGate(t, o, func(s *Settings) { s.FailPolicy = policy })
			c := g.client()
			c.write(badChunkedRequest())
			c.expectClosed()
			if len(c.rec.bytes()) != 0 {
				t.Fatalf("client received %q for a broken body", c.rec.bytes())
			}
			if o.rec.connections() != 0 {
				t.Fatal("origin dialled for a broken held body")
			}
			ev := g.events.next(t)
			expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonUnsupported, avscan.Block)
			if !strings.Contains(ev.Detail, "chunk") || ev.Size != 5 {
				t.Fatalf("event %+v", ev)
			}
		})
		t.Run("streamed", func(t *testing.T) {
			closed := make(chan error, 1)
			o := rawOrigin(t, func(c net.Conn, _ int) {
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err := io.Copy(io.Discard, c)
				closed <- err
			})
			g := startGate(t, o, func(s *Settings) { s.FailPolicy = policy; s.ScanUploads = false })
			c := g.client()
			c.write(badChunkedRequest())
			c.expectClosed()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatalf("origin read ended with %v, want EOF after the gate closed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("origin connection not closed")
			}
			got := o.rec.bytes()
			if !bytes.HasSuffix(got, []byte("5\r\nhello\r\n")) {
				t.Fatalf("origin received %q", got)
			}
			ev := g.events.next(t)
			if ev.Error == "" && ev.Verdict == "" {
				t.Fatalf("event %+v", ev)
			}
		})
	})
}

func TestTrailersPresentMidBodyClosesBoth(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.FailPolicy = avscan.FailOpen })
	c := g.client()
	c.write([]byte("POST /t HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n"))
	c.expectClosed()
	if o.rec.connections() != 0 {
		t.Fatal("origin dialled")
	}
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonUnsupported, avscan.Block)
	if !strings.Contains(ev.Detail, "trailers present") {
		t.Fatalf("event detail %q", ev.Detail)
	}
}

func TestEarlyEOFOnContentLengthBody(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.FailPolicy = avscan.FailOpen })
	c := g.client()
	req := requestCL("POST", "/short", "", pattern(1000, 61))
	c.write(req[:len(req)-400])
	_ = c.conn.(*recConn).CloseWrite()
	c.expectClosed()
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonUnsupported, avscan.Block)
	if !strings.Contains(ev.Detail, "early EOF") || ev.Size != 600 || !ev.SHA256Partial {
		t.Fatalf("event %+v", ev)
	}
	if o.rec.connections() != 0 {
		t.Fatal("origin dialled for an incomplete body")
	}
}

func TestSlowDripHitsObjectDeadline(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) {
		s.IdleTimeout = 2 * time.Second
		s.ObjectTimeout = 400 * time.Millisecond
	})
	c := g.client()
	c.write([]byte("POST /drip HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 100000\r\n\r\n"))
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for time.Since(start) < 3*time.Second {
			if _, err := c.conn.Write([]byte("0123456789")); err != nil {
				return
			}
			time.Sleep(40 * time.Millisecond)
		}
	}()
	ev := g.events.next(t)
	elapsed := time.Since(start)
	<-done
	expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonTimeout, avscan.Block)
	if ev.Detail != "object deadline exceeded" {
		t.Fatalf("detail %q", ev.Detail)
	}
	if elapsed < 350*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Fatalf("object deadline fired after %v", elapsed)
	}
	if o.rec.connections() != 0 {
		t.Fatal("origin dialled for a timed-out body")
	}
}

func TestIdleGapHitsIdleTimeout(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) {
		s.IdleTimeout = 300 * time.Millisecond
		s.ObjectTimeout = 10 * time.Second
	})
	c := g.client()
	c.write([]byte("POST /gap HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 20\r\n\r\n0123456789"))
	start := time.Now()
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonTimeout, avscan.Block)
	if ev.Detail != "idle timeout while receiving body" || ev.Size != 10 {
		t.Fatalf("event %+v", ev)
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("idle timeout fired after %v", elapsed)
	}
	c.expectClosed()
}

func TestOriginalDstErrorClosesConnection(t *testing.T) {
	g := startGate(t, &origin{rec: &recorder{}, dst: func(net.Conn) (netip.AddrPort, error) {
		return netip.AddrPort{}, fmt.Errorf("no SO_ORIGINAL_DST")
	}}, nil)
	c := g.client()
	c.write(getRequest("/x", ""))
	c.expectClosed()
	ev := g.events.next(t)
	if ev.Verdict != "" || !strings.Contains(ev.Error, "original destination: no SO_ORIGINAL_DST") {
		t.Fatalf("event %+v", ev)
	}
}

func TestPanicInHookIsRecovered(t *testing.T) {
	var calls atomic.Int32
	g := startGate(t, &origin{rec: &recorder{}, dst: func(net.Conn) (netip.AddrPort, error) {
		if calls.Add(1) == 1 {
			panic("hook exploded")
		}
		return netip.AddrPort{}, fmt.Errorf("still here")
	}}, nil)
	c := g.client()
	c.write(getRequest("/x", ""))
	c.expectClosed()
	ev := g.events.next(t)
	if !strings.Contains(ev.Error, "panic: hook exploded") || ev.Action != avscan.Block {
		t.Fatalf("event %+v", ev)
	}
	// The server keeps serving other connections.
	c2 := g.client()
	c2.write(getRequest("/y", ""))
	c2.expectClosed()
	if ev := g.events.next(t); !strings.Contains(ev.Error, "still here") {
		t.Fatalf("event %+v", ev)
	}
}
