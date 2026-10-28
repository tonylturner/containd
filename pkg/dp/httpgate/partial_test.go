// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// A partial object (206, or any response with Content-Range) is never
// scanned: it follows the fail policy in both download modes.
func TestPartialObjectFollowsPolicy(t *testing.T) {
	body := pattern(streamBody, 401)
	for _, mode := range []DownloadMode{DownloadHold, DownloadStreamTail} {
		for _, status := range []int{206, 200} {
			forPolicies(t, func(t *testing.T, policy avscan.FailPolicy) {
				t.Run(fmt.Sprintf("%s-%d", mode, status), func(t *testing.T) {
					o := httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(body)-1, 2*len(body)))
						w.Header().Set("Content-Length", fmt.Sprint(len(body)))
						w.WriteHeader(status)
						_, _ = w.Write(body)
					}))
					g := startGate(t, o, func(s *Settings) { s.DownloadMode = mode; s.FailPolicy = policy })
					c := g.client()
					c.write(getRequest("/part", "Range: bytes=0-524287\r\n"))
					resp, rb := c.response("GET")
					ev := g.events.next(t)
					expectEvent(t, ev, avscan.Download, avscan.Unscanned, avscan.ReasonUnsupported, unscannedAction(policy))
					if ev.Status != status || !strings.Contains(ev.Detail, "partial object") || ev.Backend != "gate" || ev.Streamed != 0 {
						t.Fatalf("event %+v", ev)
					}
					if len(g.scanner.scanCalls()) != 0 {
						t.Fatal("a partial object was scanned")
					}
					if policy == avscan.FailClosed {
						if resp.StatusCode != 403 || !strings.Contains(string(rb), "unsupported") || ev.Size != int64(len(body)) {
							t.Fatalf("status %d body %q event size %d", resp.StatusCode, rb, ev.Size)
						}
						c.expectEOF()
						return
					}
					if resp.StatusCode != status || !bytes.Equal(rb, body) || ev.Size != int64(len(body)) || !ev.SHA256Partial {
						t.Fatalf("status %d, %d bytes, event %+v", resp.StatusCode, len(rb), ev)
					}
				})
			})
		}
	}
}

// A relayed body the origin fails to complete resets the client instead
// of closing it: with close-delimited framing a FIN would turn the
// prefix into a complete-looking object. Covers the oversized
// pass-through under fail-open and the unselected relay alike.
func TestRelayedBodyOriginFailureResetsClient(t *testing.T) {
	const cap = 128 << 10
	body := pattern(2*cap, 402)
	for _, tc := range []struct {
		name   string
		adjust func(*Settings)
		event  bool
	}{
		{"oversized-pass", func(s *Settings) { s.FailPolicy = avscan.FailOpen; s.MaxObjectBytes = cap }, true},
		{"downloads-unselected", func(s *Settings) { s.ScanDownloads = false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stall := make(chan struct{})
			t.Cleanup(func() { close(stall) })
			o := rawOrigin(t, func(c net.Conn, _ int) {
				if _, _, err := readRequestHead(c); err != nil {
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"))
				_, _ = c.Write(body)
				// The origin stalls without closing: the gate's idle
				// timeout is the only way the relay ends.
				<-stall
			})
			g := startGate(t, o, func(s *Settings) { tc.adjust(s); s.IdleTimeout = 300 * time.Millisecond })
			c := g.client()
			c.write(getRequest("/stalled", ""))
			_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			h, got, err := decodeResponse(t, nil, c.conn, "GET")
			if h.status != 200 || !errors.Is(err, syscall.ECONNRESET) || len(got) > len(body) || !bytes.Equal(got, body[:len(got)]) {
				t.Fatalf("status %d, %d bytes, err %v: want a prefix of the body then a reset", h.status, len(got), err)
			}
			if !tc.event {
				g.events.expectNone(t, 100*time.Millisecond)
				return
			}
			ev := g.events.next(t)
			expectEvent(t, ev, avscan.Download, avscan.Unscanned, avscan.ReasonOversized, avscan.PassUnscanned)
			if !ev.SHA256Partial || ev.Size != int64(len(body)) {
				t.Fatalf("event %+v", ev)
			}
		})
	}
}
