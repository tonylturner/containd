// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"

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
