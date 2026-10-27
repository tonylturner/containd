// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// streamBody is a download longer than the tail by several copy buffers.
const streamBody = 512 << 10

// streamTail configures stream_tail downloads under policy.
func streamTail(policy avscan.FailPolicy) func(*Settings) {
	return func(s *Settings) { s.DownloadMode = DownloadStreamTail; s.FailPolicy = policy }
}

// readAvailable returns what the gate has sent so far: it reads until
// the connection stays quiet for the window. Bytes the gate wrote before
// the call are in the kernel already, so the window only pads delivery.
func (c *client) readAvailable(quiet time.Duration) []byte {
	c.t.Helper()
	var got []byte
	buf := make([]byte, copyBufSize)
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(quiet))
		n, err := c.conn.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if !isTimeout(err) {
				c.t.Fatalf("read while the gate holds the tail: %v", err)
			}
			return got
		}
	}
}

// expectReset asserts that the gate reset the connection rather than
// closing it.
func (c *client) expectReset() {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.conn.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, syscall.ECONNRESET) {
		c.t.Fatalf("expected a reset from the gate, got n=%d err=%v", n, err)
	}
}

// decodeResponse parses one response from raw followed by what more
// yields and returns the decoded body; err reports a body that more did
// not complete.
func decodeResponse(t *testing.T, raw []byte, more io.Reader, method string) (*head, []byte, error) {
	t.Helper()
	br := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(raw), more), headCap)
	headRaw, err := readHead(br)
	if err != nil {
		t.Fatalf("response head: %v (%d bytes)", err, len(raw))
	}
	h, err := parseResponseHead(headRaw, method)
	if err != nil {
		t.Fatalf("response head: %v", err)
	}
	body, err := io.ReadAll(newBodyReader(h, br))
	return h, body, err
}

// streamOrigins are the three response framings serving body; the raw
// one reports the error of its read after the body on originErr.
func streamOrigins(t *testing.T, body []byte) []struct {
	name   string
	origin func(t *testing.T, originErr chan error) *origin
	closes bool
} {
	return []struct {
		name   string
		origin func(t *testing.T, originErr chan error) *origin
		closes bool
	}{
		{
			name: "content-length",
			origin: func(t *testing.T, _ chan error) *origin {
				return httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", fmt.Sprint(len(body)))
					_, _ = w.Write(body)
				}))
			},
		},
		{
			name: "chunked",
			origin: func(t *testing.T, _ chan error) *origin {
				return httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for off := 0; off < len(body); off += 100_000 {
						_, _ = w.Write(body[off:min(off+100_000, len(body))])
						w.(http.Flusher).Flush()
					}
				}))
			},
		},
		{
			name: "close-delimited",
			origin: func(t *testing.T, originErr chan error) *origin {
				return rawOrigin(t, func(c net.Conn, _ int) {
					if _, _, err := readRequestHead(c); err != nil {
						return
					}
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"))
					_, _ = c.Write(body)
					// Half-close ends the body; the read then sees how the
					// gate ended the connection.
					_ = c.(*recConn).CloseWrite()
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					_, err := c.Read(make([]byte, 1))
					originErr <- err
				})
			},
			closes: true,
		},
	}
}

// A clean stream_tail download reaches the client whole: all but the
// tail before the verdict, the tail after it, in the original framing.
func TestStreamTailCleanDownloadArrivesIntact(t *testing.T) {
	body := pattern(streamBody, 201)
	for _, tc := range streamOrigins(t, body) {
		t.Run(tc.name, func(t *testing.T) {
			originErr := make(chan error, 1)
			o := tc.origin(t, originErr)
			g := startGate(t, o, streamTail(avscan.FailClosed))
			release := g.scanner.holdScans()
			c := g.client()
			c.write(getRequest("/big", ""))
			g.scanner.waitScanStarted(t)
			prefix := c.readAvailable(200 * time.Millisecond)
			_, got, _ := decodeResponse(t, prefix, bytes.NewReader(nil), "GET")
			if want := body[:len(body)-streamTailBytes]; !bytes.Equal(got, want) {
				t.Fatalf("client holds %d body bytes before the verdict, want %d", len(got), len(want))
			}
			release()
			_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			h, full, err := decodeResponse(t, prefix, c.conn, "GET")
			if err != nil || h.status != 200 || !bytes.Equal(full, body) {
				t.Fatalf("status %d body %d bytes identical=%v err=%v", h.status, len(full), bytes.Equal(full, body), err)
			}
			ev := g.events.next(t)
			expectEvent(t, ev, avscan.Download, avscan.Clean, "", avscan.Deliver)
			if ev.Streamed != streamBody-streamTailBytes || ev.Size != streamBody || ev.SHA256 != sha256hex(body) || ev.SHA256Partial {
				t.Fatalf("event %+v", ev)
			}
			if tc.closes {
				c.expectEOF()
				return
			}
			c.write(getRequest("/again", ""))
			resp, rb := c.response("GET")
			if resp.StatusCode != 200 || !bytes.Equal(rb, body) {
				t.Fatalf("second transaction: status %d, %d bytes", resp.StatusCode, len(rb))
			}
		})
	}
}

// An infected stream_tail download stops at the tail: the client has at
// most the prefix, then both connections are reset, and the URL is
// refused afterwards so the tail cannot be fetched with a Range request.
func TestStreamTailInfectedDownloadReset(t *testing.T) {
	body := append(pattern(streamBody-len(infectedMarker), 202), []byte(infectedMarker)...)
	for _, tc := range streamOrigins(t, body) {
		t.Run(tc.name, func(t *testing.T) {
			originErr := make(chan error, 1)
			o := tc.origin(t, originErr)
			g := startGate(t, o, streamTail(avscan.FailOpen))
			release := g.scanner.holdScans()
			c := g.client()
			c.write(getRequest("/malware?v=1", ""))
			g.scanner.waitScanStarted(t)
			prefix := c.readAvailable(200 * time.Millisecond)
			_, got, _ := decodeResponse(t, prefix, bytes.NewReader(nil), "GET")
			if len(got) != len(body)-streamTailBytes || bytes.Contains(got, []byte(infectedMarker)) {
				t.Fatalf("client holds %d body bytes before the verdict", len(got))
			}
			release()
			c.expectReset()
			ev := g.events.next(t)
			expectEvent(t, ev, avscan.Download, avscan.Infected, "", avscan.Block)
			if ev.Signature != testSignature || ev.Streamed != int64(len(got)) || ev.Size != int64(len(body)) || ev.SHA256 != sha256hex(body) {
				t.Fatalf("event %+v", ev)
			}
			if tc.closes {
				// Only the raw origin can observe how its connection ended.
				select {
				case err := <-originErr:
					if !errors.Is(err, syscall.ECONNRESET) {
						t.Fatalf("origin saw %v, want a reset", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("origin read did not return")
				}
			}

			retry := g.client()
			retry.write(getRequest("/malware?v=1", "Range: bytes=458752-\r\n"))
			resp, rb := retry.response("GET")
			if resp.StatusCode != 403 || !strings.Contains(string(rb), "recently infected") {
				t.Fatalf("retry: status %d body %q", resp.StatusCode, rb)
			}
			retry.expectEOF()
			ev = g.events.next(t)
			expectEvent(t, ev, avscan.Download, avscan.Infected, ReasonRecentlyInfected, avscan.Block)
			if ev.Signature != testSignature || ev.Backend != "gate" || ev.Detail != recentlyInfectedDetail || ev.Target != "/malware?v=1" {
				t.Fatalf("event %+v", ev)
			}
			if o.rec.connections() != 1 || len(g.scanner.scanCalls()) != 1 {
				t.Fatalf("retry reached the origin (%d connections) or the scanner (%d calls)", o.rec.connections(), len(g.scanner.scanCalls()))
			}
		})
	}
}

// A scanner error during a stream_tail download follows the fail policy:
// reset under closed, the tail delivered as unscanned under open.
func TestStreamTailScannerErrorFollowsPolicy(t *testing.T) {
	body := pattern(streamBody, 203)
	forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
		o := httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(body)
		}))
		g := startGate(t, o, streamTail(policy))
		g.scanner.setVerdict(func(avscan.Object, []byte) avscan.Result {
			return avscan.Result{Verdict: avscan.Unscanned, Reason: avscan.ReasonScannerError, Backend: "fake", Detail: "clamd: broken pipe"}
		})
		c := g.client()
		c.write(getRequest("/err", ""))
		ev := g.events.next(t)
		expectEvent(t, ev, avscan.Download, avscan.Unscanned, avscan.ReasonScannerError, unscannedAction(policy))
		if ev.Streamed != streamBody-streamTailBytes || ev.Size != streamBody {
			t.Fatalf("event %+v", ev)
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		h, got, err := decodeResponse(t, nil, c.conn, "GET")
		if policy == avscan.FailClosed {
			// The reset discards what the gate had not transmitted yet, so
			// the client holds at most the prefix.
			if !errors.Is(err, syscall.ECONNRESET) || len(got) > streamBody-streamTailBytes || !bytes.Equal(got, body[:len(got)]) {
				t.Fatalf("fail-closed: %d body bytes, err %v, want at most the prefix then a reset", len(got), err)
			}
			return
		}
		if err != nil || h.status != 200 || !bytes.Equal(got, body) {
			t.Fatalf("fail-open: status %d, %d bytes, err %v", h.status, len(got), err)
		}
	})
}

// A client that leaves while its download streams ends the transaction:
// the origin is reset and the abort is recorded with the streamed count.
func TestStreamTailClientCloseMidStreamAborts(t *testing.T) {
	body := pattern(2<<20, 204)
	first := 256 << 10
	clientGone := make(chan struct{})
	originErr := make(chan error, 1)
	o := rawOrigin(t, func(c net.Conn, _ int) {
		if _, _, err := readRequestHead(c); err != nil {
			return
		}
		_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
		_, _ = c.Write(body[:first])
		<-clientGone
		var err error
		for off := first; off < len(body) && err == nil; off += 128 << 10 {
			_, err = c.Write(body[off:min(off+128<<10, len(body))])
			time.Sleep(20 * time.Millisecond)
		}
		originErr <- err
	})
	g := startGate(t, o, streamTail(avscan.FailOpen))
	c := g.client()
	c.write(getRequest("/leave", ""))
	prefix := c.readAvailable(200 * time.Millisecond)
	_, got, _ := decodeResponse(t, prefix, bytes.NewReader(nil), "GET")
	if len(got) != first-streamTailBytes {
		t.Fatalf("client holds %d body bytes, want %d", len(got), first-streamTailBytes)
	}
	c.conn.Close()
	close(clientGone)
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Download, avscan.Unscanned, avscan.ReasonAborted, avscan.Block)
	if !strings.HasPrefix(ev.Detail, "client stopped taking the streamed body") || ev.Streamed < int64(len(got)) || !ev.SHA256Partial {
		t.Fatalf("event %+v", ev)
	}
	select {
	case err := <-originErr:
		if err == nil {
			t.Fatal("origin wrote the whole body after the client left")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("origin write did not fail")
	}
	if len(g.scanner.scanCalls()) != 0 {
		t.Fatal("an incomplete body was scanned")
	}
}

// Uploads are held in stream_tail mode exactly as in hold mode.
func TestStreamTailUploadStillHeld(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, streamTail(avscan.FailOpen))
	release := g.scanner.holdScans()
	body := append(pattern(streamBody, 205), []byte(infectedMarker)...)
	c := g.client()
	c.write(requestCL("POST", "/malware", "", body))
	g.scanner.waitScanStarted(t)
	c.expectSilence(100 * time.Millisecond)
	if n := o.rec.connections(); n != 0 {
		t.Fatalf("origin accepted %d connections before the upload verdict", n)
	}
	release()
	resp, rb := c.response("POST")
	if resp.StatusCode != 403 || !strings.Contains(string(rb), testSignature) {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	c.expectEOF()
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Upload, avscan.Infected, "", avscan.Block)
	if ev.Streamed != 0 || o.rec.connections() != 0 || len(log.list()) != 0 {
		t.Fatalf("event %+v, origin connections %d", ev, o.rec.connections())
	}

	clean := pattern(streamBody, 206)
	c = g.client()
	c.write(requestCL("POST", "/clean", "", clean))
	resp, rb = c.response("POST")
	if resp.StatusCode != 200 || string(rb) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	if got := log.list(); len(got) != 1 || !bytes.Equal(got[0].body, clean) {
		t.Fatal("origin did not receive the identical clean upload")
	}
}

// Hold mode is the default and delivers nothing before the verdict.
func TestHoldModeDefaultDeliversNothingEarly(t *testing.T) {
	body := pattern(streamBody, 207)
	o := httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	g := startGate(t, o, nil)
	if mode := g.srv.settings.Load().DownloadMode; mode != DownloadHold {
		t.Fatalf("default download mode %q", mode)
	}
	release := g.scanner.holdScans()
	c := g.client()
	c.write(getRequest("/held", ""))
	g.scanner.waitScanStarted(t)
	c.expectSilence(100 * time.Millisecond)
	release()
	resp, rb := c.response("GET")
	if resp.StatusCode != 200 || !bytes.Equal(rb, body) {
		t.Fatalf("status %d, %d bytes", resp.StatusCode, len(rb))
	}
	if ev := g.events.next(t); ev.Streamed != 0 || ev.Action != avscan.Deliver {
		t.Fatalf("event %+v", ev)
	}
}
