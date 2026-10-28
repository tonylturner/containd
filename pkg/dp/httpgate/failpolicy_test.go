// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// forPolicies runs fn once per fail policy.
func forPolicies(t *testing.T, fn func(t *testing.T, policy avscan.FailPolicy)) {
	for _, p := range []avscan.FailPolicy{avscan.FailClosed, avscan.FailOpen} {
		t.Run(string(p), func(t *testing.T) { fn(t, p) })
	}
}

func unscannedAction(policy avscan.FailPolicy) avscan.Action {
	if policy == avscan.FailOpen {
		return avscan.PassUnscanned
	}
	return avscan.Block
}

// expectRefusedOrDelivered checks the client outcome of an unscanned
// upload: a 403 under closed, the origin's 200 under open.
func expectRefusedOrDelivered(t *testing.T, c *client, policy avscan.FailPolicy, reason avscan.Reason) {
	t.Helper()
	resp, rb := c.response("POST")
	if policy == avscan.FailClosed {
		if resp.StatusCode != 403 || !strings.Contains(string(rb), string(reason)) {
			t.Fatalf("status %d body %q", resp.StatusCode, rb)
		}
		c.expectEOF()
		return
	}
	if resp.StatusCode != 200 || string(rb) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
}

func TestScannerErrorFollowsPolicy(t *testing.T) {
	forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
		log := &bodyLog{}
		o := echoOrigin(t, log)
		g := startGate(t, o, func(s *Settings) { s.FailPolicy = policy; s.ScanDownloads = false })
		g.scanner.setVerdict(func(avscan.Object, []byte) avscan.Result {
			return avscan.Result{Verdict: avscan.Unscanned, Reason: avscan.ReasonScannerError, Backend: "fake", Detail: "clamd: broken pipe"}
		})
		body := pattern(300_000, 41)
		c := g.client()
		c.write(requestCL("POST", "/err", "", body))
		expectRefusedOrDelivered(t, c, policy, avscan.ReasonScannerError)
		ev := g.events.next(t)
		expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonScannerError, unscannedAction(policy))
		if ev.Detail != "clamd: broken pipe" || ev.Backend != "fake" || ev.SHA256 != sha256hex(body) {
			t.Fatalf("event %+v", ev)
		}
		got := log.list()
		if policy == avscan.FailClosed && (len(got) != 0 || o.rec.connections() != 0) {
			t.Fatal("origin reached under fail-closed")
		}
		if policy == avscan.FailOpen && (len(got) != 1 || !bytes.Equal(got[0].body, body)) {
			t.Fatal("origin did not receive the identical body under fail-open")
		}
	})
}

func TestScanTimeoutFollowsPolicy(t *testing.T) {
	forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
		log := &bodyLog{}
		o := echoOrigin(t, log)
		g := startGate(t, o, func(s *Settings) {
			s.FailPolicy = policy
			s.ScanDownloads = false
			s.ScanTimeout = 150 * time.Millisecond
		})
		g.scanner.holdScans()
		c := g.client()
		c.write(requestCL("POST", "/slow", "", pattern(1000, 42)))
		expectRefusedOrDelivered(t, c, policy, avscan.ReasonTimeout)
		ev := g.events.next(t)
		expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonTimeout, unscannedAction(policy))
		calls := g.scanner.scanCalls()
		if len(calls) != 1 || !errors.Is(calls[0].ctxErr, context.DeadlineExceeded) {
			t.Fatalf("scan calls %+v", calls)
		}
	})
}

func TestNotReadyFollowsPolicy(t *testing.T) {
	forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
		log := &bodyLog{}
		o := echoOrigin(t, log)
		g := startGate(t, o, func(s *Settings) { s.FailPolicy = policy; s.ScanDownloads = false })
		g.scanner.setNotReady("clamd unreachable")
		body := pattern(200_000, 43)
		c := g.client()
		c.write(requestChunked("POST", "/notready", "", body, 1000))
		expectRefusedOrDelivered(t, c, policy, avscan.ReasonNotReady)
		ev := g.events.next(t)
		expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonNotReady, unscannedAction(policy))
		if ev.Backend != "gate" || ev.Detail != "clamd unreachable" {
			t.Fatalf("event %+v", ev)
		}
		if len(g.scanner.scanCalls()) != 0 {
			t.Fatal("Scan called while not ready")
		}
		if policy == avscan.FailOpen {
			got := log.list()
			if len(got) != 1 || !bytes.Equal(got[0].body, body) || got[0].framing != "chunked" {
				t.Fatalf("origin got %+v", got)
			}
			if ev.Size != int64(len(body)) {
				t.Fatalf("event size %d", ev.Size)
			}
		}
	})
}

func TestOversizedUploadFollowsPolicy(t *testing.T) {
	body := pattern(threeMiB, 44)
	for _, framing := range []string{"content-length", "chunked"} {
		forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
			t.Run(framing, func(t *testing.T) {
				log := &bodyLog{}
				o := echoOrigin(t, log)
				g := startGate(t, o, func(s *Settings) {
					s.FailPolicy = policy
					s.ScanDownloads = false
					s.MaxObjectBytes = 1 << 20
				})
				c := g.client()
				req := requestCL("POST", "/big", "", body)
				if framing == "chunked" {
					req = requestChunked("POST", "/big", "", body, 100_000)
				}
				go func() {
					_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					_, _ = c.conn.Write(req)
				}()
				expectRefusedOrDelivered(t, c, policy, avscan.ReasonOversized)
				ev := g.events.next(t)
				expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonOversized, unscannedAction(policy))
				if ev.Backend != "gate" || len(g.scanner.scanCalls()) != 0 {
					t.Fatalf("event %+v, scans %d", ev, len(g.scanner.scanCalls()))
				}
				if policy == avscan.FailClosed {
					if o.rec.connections() != 0 {
						t.Fatal("origin reached for a refused oversized upload")
					}
					// A declared length over the cap is refused unread; a chunked
					// body is refused after its 1 MiB prefix was held and hashed.
					wantHash, wantSize := "", int64(threeMiB)
					if framing == "chunked" {
						wantHash, wantSize = sha256hex(body[:1<<20]), 1<<20
					}
					if !ev.SHA256Partial || ev.SHA256 != wantHash || ev.Size != wantSize {
						t.Fatalf("refused prefix digest not marked partial: %+v", ev)
					}
					return
				}
				got := log.list()
				if len(got) != 1 || !bytes.Equal(got[0].body, body) {
					t.Fatal("origin did not receive the identical oversized body")
				}
				wantFraming := fmt.Sprintf("length=%d", threeMiB)
				if framing == "chunked" {
					wantFraming = "chunked"
				}
				if got[0].framing != wantFraming {
					t.Fatalf("origin framing %q", got[0].framing)
				}
				if ev.Size != threeMiB || !ev.SHA256Partial {
					t.Fatalf("event %+v", ev)
				}
				if framing == "chunked" && ev.SHA256 != sha256hex(body[:1<<20]) {
					t.Fatalf("partial hash %s does not cover the held 1 MiB prefix", ev.SHA256)
				}
			})
		})
	}
}

func TestOversizedDownloadFollowsPolicy(t *testing.T) {
	body := pattern(threeMiB, 45)
	for _, framing := range []string{"content-length", "chunked"} {
		forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
			t.Run(framing, func(t *testing.T) {
				o := httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if framing == "content-length" {
						w.Header().Set("Content-Length", fmt.Sprint(len(body)))
						_, _ = w.Write(body)
						return
					}
					for off := 0; off < len(body); off += 100_000 {
						_, _ = w.Write(body[off:min(off+100_000, len(body))])
						w.(http.Flusher).Flush()
					}
				}))
				g := startGate(t, o, func(s *Settings) {
					s.FailPolicy = policy
					s.MaxObjectBytes = 1 << 20
				})
				c := g.client()
				c.write(getRequest("/big", ""))
				resp, rb := c.response("GET")
				ev := g.events.next(t)
				expectEvent(t, ev, avscan.Download, avscan.Unscanned, avscan.ReasonOversized, unscannedAction(policy))
				if policy == avscan.FailClosed {
					if resp.StatusCode != 403 || bytes.Contains(c.rec.bytes(), body[:4096]) {
						t.Fatalf("status %d, leaked=%v", resp.StatusCode, bytes.Contains(c.rec.bytes(), body[:4096]))
					}
					c.expectEOF()
					wantHash, wantSize := "", int64(threeMiB)
					if framing == "chunked" {
						wantHash, wantSize = sha256hex(body[:1<<20]), 1<<20
					}
					if !ev.SHA256Partial || ev.SHA256 != wantHash || ev.Size != wantSize {
						t.Fatalf("refused prefix digest not marked partial: %+v", ev)
					}
					return
				}
				if resp.StatusCode != 200 || !bytes.Equal(rb, body) {
					t.Fatalf("status %d identical=%v", resp.StatusCode, bytes.Equal(rb, body))
				}
				if framing == "chunked" && strings.Join(resp.TransferEncoding, ",") != "chunked" {
					t.Fatalf("transfer-encoding %v", resp.TransferEncoding)
				}
				if framing == "content-length" && resp.ContentLength != threeMiB {
					t.Fatalf("content-length %d", resp.ContentLength)
				}
				if ev.Size != threeMiB || !ev.SHA256Partial {
					t.Fatalf("event %+v", ev)
				}
			})
		})
	}
}

// A spool that cannot open its file refuses as busy under closed policy;
// the digest of the bytes held in memory is marked partial.
func TestSpoolDiskErrorRefusalIsPartial(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) {
		s.ScanDownloads = false
		s.MemoryThreshold = 1024
		s.SpoolDir = "/nonexistent/httpgate-spool"
	})
	body := pattern(5000, 53)
	c := g.client()
	c.write(requestCL("POST", "/disk", "", body))
	expectRefusedOrDelivered(t, c, avscan.FailClosed, avscan.ReasonBusy)
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonBusy, avscan.Block)
	// The first write already exceeds the threshold, so nothing was held:
	// the object is still reported by its declared length as partial.
	if ev.Backend != "gate" || ev.SHA256 != "" || !ev.SHA256Partial || ev.Size != int64(len(body)) {
		t.Fatalf("event %+v", ev)
	}
	if o.rec.connections() != 0 {
		t.Fatal("origin reached for a refused upload")
	}
}

func TestBusyObjectLimitFollowsPolicy(t *testing.T) {
	forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
		log := &bodyLog{}
		o := echoOrigin(t, log)
		g := startGate(t, o, func(s *Settings) {
			s.FailPolicy = policy
			s.ScanDownloads = false
			s.MaxConcurrentObjects = 1
		})
		release := g.scanner.holdScans()
		first := g.client()
		first.write(requestCL("POST", "/first", "", pattern(1000, 46)))
		g.scanner.waitScanStarted(t)
		second := g.client()
		body := pattern(2000, 47)
		second.write(requestCL("POST", "/second", "", body))
		expectRefusedOrDelivered(t, second, policy, avscan.ReasonBusy)
		ev := g.events.next(t)
		expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonBusy, unscannedAction(policy))
		if ev.Target != "/second" || ev.Backend != "gate" {
			t.Fatalf("event %+v", ev)
		}
		release()
		if resp, rb := first.response("POST"); resp.StatusCode != 200 || string(rb) != "ok" {
			t.Fatalf("first upload: %d %q", resp.StatusCode, rb)
		}
		ev = g.events.next(t)
		expectEvent(t, ev, avscan.Upload, avscan.Clean, "", avscan.Deliver)
		// The slot is free again: a third upload is held normally.
		third := g.client()
		third.write(requestCL("POST", "/third", "", pattern(10, 48)))
		if resp, _ := third.response("POST"); resp.StatusCode != 200 {
			t.Fatalf("third upload status %d", resp.StatusCode)
		}
		ev = g.events.next(t)
		expectEvent(t, ev, avscan.Upload, avscan.Clean, "", avscan.Deliver)
	})
}

// MaxConnections is a hard admission bound: a connection over it is
// closed at accept time with nothing allocated for it, a flood of them
// yields one bounded-rate event, and the limit-holding connection keeps
// working.
func TestConnectionLimitRefusesAtAccept(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.ScanDownloads = false; s.MaxConnections = 1 })
	first := g.client()
	first.write(requestCL("POST", "/within", "", pattern(100, 50)))
	if resp, _ := first.response("POST"); resp.StatusCode != 200 {
		t.Fatalf("within-limit connection status %d", resp.StatusCode)
	}
	expectEvent(t, g.events.next(t), avscan.Upload, avscan.Clean, "", avscan.Deliver)
	var refused []*client
	for range 20 {
		c := g.client()
		c.write([]byte("G"))
		refused = append(refused, c)
	}
	for _, c := range refused {
		c.expectClosed()
	}
	ev := g.events.next(t)
	if ev.Verdict != "" || ev.Action != avscan.Block || !strings.Contains(ev.Error, "connection limit reached") {
		t.Fatalf("event %+v", ev)
	}
	g.events.expectNone(t, 100*time.Millisecond)
	if n := g.srv.activeConns.Load(); n != 1 {
		t.Fatalf("active connections %d, want the one within the limit", n)
	}
	first.write(requestCL("POST", "/again", "", pattern(100, 51)))
	if resp, _ := first.response("POST"); resp.StatusCode != 200 {
		t.Fatalf("within-limit connection status %d after the flood", resp.StatusCode)
	}
	expectEvent(t, g.events.next(t), avscan.Upload, avscan.Clean, "", avscan.Deliver)
}

// A connection draining after its refusal still occupies its slot.
func TestRefusalDrainCountsAgainstConnectionLimit(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.ScanDownloads = false; s.MaxConnections = 1 })
	first := g.client()
	first.write(requestCL("POST", "/bad", "", []byte(infectedMarker)))
	if resp, _ := first.response("POST"); resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	expectEvent(t, g.events.next(t), avscan.Upload, avscan.Infected, "", avscan.Block)
	// The gate half-closed and is draining first; a newcomer is refused.
	second := g.client()
	second.write(getRequest("/over", ""))
	second.expectClosed()
	if ev := g.events.next(t); !strings.Contains(ev.Error, "connection limit reached") {
		t.Fatalf("event %+v", ev)
	}
	first.expectEOF()
}

// bigHeadRequest is a request whose head exceeds the 64 KiB cap.
func bigHeadRequest() []byte {
	return []byte("GET /big HTTP/1.1\r\nHost: origin.test\r\nX-Pad: " + strings.Repeat("a", 70<<10) + "\r\n\r\n")
}

func TestUnsupportedRequestsFollowPolicy(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"h2-preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")},
		{"connect", []byte("CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n")},
		{"upgrade", []byte("GET /ws HTTP/1.1\r\nHost: origin.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")},
		{"cl-and-te", []byte("POST /x HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")},
		{"head-over-cap", bigHeadRequest()},
		{"trailers-declared", []byte("POST /x HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n0\r\n\r\n")},
		{"obs-fold", []byte("GET /x HTTP/1.1\r\nHost: origin.test\r\nX-A: 1\r\n 2\r\n\r\n")},
		{"connection-nominates-framing", []byte("GET /x HTTP/1.1\r\nHost: origin.test\r\nConnection: Content-Length\r\n\r\n")},
		{"duplicate-cl", []byte("POST /x HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na")},
		{"bare-lf", []byte("GET /x HTTP/1.1\nHost: origin.test\n\n")},
		{"http10-te", []byte("POST /x HTTP/1.0\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n")},
		{"authority-mismatch", []byte("GET http://real.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")},
	}
	for _, tc := range cases {
		forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
			t.Run(tc.name, func(t *testing.T) {
				o := rawOrigin(t, func(c net.Conn, _ int) {
					// Under PassUnscanned the gate splices: expect exactly the
					// client's bytes, then answer.
					buf := make([]byte, len(tc.raw))
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				})
				g := startGate(t, o, func(s *Settings) { s.FailPolicy = policy })
				c := g.client()
				c.write(tc.raw)
				resp, rb := c.response("GET")
				ev := g.events.next(t)
				expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonUnsupported, unscannedAction(policy))
				if policy == avscan.FailClosed {
					if resp.StatusCode != 400 || !resp.Close || resp.ContentLength <= 0 {
						t.Fatalf("response %+v", resp)
					}
					c.expectEOF()
					if o.rec.connections() != 0 {
						t.Fatal("origin reached for a blocked unsupported request")
					}
					return
				}
				if resp.StatusCode != 200 || string(rb) != "ok" {
					t.Fatalf("spliced response %d %q", resp.StatusCode, rb)
				}
				if got := o.rec.bytes(); !bytes.Equal(got, tc.raw) {
					t.Fatalf("origin received %d bytes, want the exact %d sent", len(got), len(tc.raw))
				}
				c.conn.Close()
			})
		})
	}
}

func TestUnsupportedResponsesFollowPolicy(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"cl-and-te", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"},
		{"101-without-upgrade", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nraw-stream"},
		{"trailers", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n0\r\n\r\n"},
		{"not-http", "SSH-2.0-OpenSSH\r\n\r\n"},
	}
	for _, tc := range cases {
		forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
			t.Run(tc.name, func(t *testing.T) {
				o := rawOrigin(t, func(c net.Conn, _ int) {
					if _, _, err := readRequestHead(c); err != nil {
						return
					}
					_, _ = io.WriteString(c, tc.raw)
				})
				g := startGate(t, o, func(s *Settings) { s.FailPolicy = policy })
				c := g.client()
				c.write(getRequest("/odd", ""))
				ev := g.events.next(t)
				expectEvent(t, ev, avscan.Download, avscan.Unscanned, avscan.ReasonUnsupported, unscannedAction(policy))
				_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				got, _ := io.ReadAll(c.br)
				if policy == avscan.FailClosed {
					if !bytes.HasPrefix(got, []byte("HTTP/1.1 502 ")) || !bytes.Contains(got, []byte("Connection: close")) {
						t.Fatalf("client got %q", got)
					}
					return
				}
				if string(got) != tc.raw {
					t.Fatalf("spliced bytes %q, want %q", got, tc.raw)
				}
			})
		})
	}
}

func TestICSBypassPassesUnscannedOnly(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	ics := func(client, server netip.Addr) bool { return server.IsLoopback() }
	for _, tc := range []struct {
		name   string
		bypass bool
		body   []byte
		ready  bool
		status int
		action avscan.Action
	}{
		{"bypass-not-ready", true, pattern(100, 51), false, 200, avscan.PassUnscanned},
		{"bypass-infected", true, []byte(infectedMarker), true, 403, avscan.Block},
		{"no-bypass-not-ready", false, pattern(100, 52), false, 403, avscan.Block},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := startGate(t, o, func(s *Settings) {
				s.ScanDownloads = false
				s.ICSBypass = tc.bypass
				s.IsICS = ics
			})
			if !tc.ready {
				g.scanner.setNotReady("down")
			}
			c := g.client()
			c.write(requestCL("POST", "/ics", "", tc.body))
			resp, _ := c.response("POST")
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
			ev := g.events.next(t)
			if ev.Action != tc.action || !ev.ICS {
				t.Fatalf("event %+v", ev)
			}
		})
	}
}

func TestDialFailureAnswers502(t *testing.T) {
	ln, addr := listenLoopback(t)
	ln.Close()
	g := startGate(t, &origin{addr: addr, rec: &recorder{}}, nil)
	c := g.client()
	c.write(getRequest("/nowhere", ""))
	resp, _ := c.response("GET")
	if resp.StatusCode != 502 || !resp.Close {
		t.Fatalf("response %+v", resp)
	}
	c.expectEOF()
	ev := g.events.next(t)
	if ev.Verdict != "" || !strings.HasPrefix(ev.Error, "dial: ") || ev.Action != avscan.Block {
		t.Fatalf("event %+v", ev)
	}
}
