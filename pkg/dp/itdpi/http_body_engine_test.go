// SPDX-License-Identifier: Apache-2.0

package itdpi_test

import (
	"fmt"
	"strings"
	"testing"
)

func TestHTTPDeclaredRequestBodyAndEarlyFinal(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		for _, framing := range []string{"Content-Length: 1000000\r\n\r\n", "Transfer-Encoding: gzip; note=\"a,b\"\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\n"} {
			t.Run(framing, func(t *testing.T) {
				h := recoveryNew(t, mode)
				h.send(false, "GET /first HTTP/1.1\r\n\r\nPOST /body HTTP/1.1\r\n"+framing)
				h.send(true, recoveryReply("application/first"))
				h.send(false, "GET /other-request-final HTTP/1.1\r\n\r\n")
				if recoveryPath(h, "/other-request-final") {
					t.Fatal("another request's final reply abandoned this body")
				}
				h.send(true, "HTTP/1.1 100 Continue\r\n\r\n")
				h.send(false, "GET /body-text HTTP/1.1\r\n\r\n")
				if recoveryPath(h, "/body-text") {
					t.Fatal("re-anchored inside a declared body after an interim reply")
				}
				h.send(true, "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n")
				h.send(false, "GET /after HTTP/1.1\r\n\r\n")
				h.send(true, recoveryReply("application/after"))
				recoveryCheck(t, h, "/after", "application/after")
				if recoveryCount(h, "malformed") != 0 {
					t.Fatal(h.events())
				}
			})
		}
	})
}

func TestHTTPDeclaredResponseBodyOwnsPacketBoundaries(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprint(chunked), func(t *testing.T) {
				h := recoveryNew(t, mode)
				fake := recoveryReply("application/body-text")
				h.send(false, "GET /first HTTP/1.1\r\n\r\nGET /after HTTP/1.1\r\n\r\n")
				if chunked {
					h.send(true, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"+fmt.Sprintf("%x\r\n", len(fake)))
				} else {
					h.send(true, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(fake)))
				}
				h.send(true, fake)
				if chunked {
					h.send(true, "\r\n0\r\n\r\n")
				}
				h.send(true, recoveryReply("application/after"))
				recoveryCheck(t, h, "/after", "application/after")
				if recoveryContent(h, "application/body-text") || recoveryCount(h, "response") != 2 || recoveryCount(h, "malformed") != 0 {
					t.Fatal(h.events())
				}
			})
		}
	})
}

func TestHTTPFramingErrorsRecoverWithoutFlooding(t *testing.T) {
	for _, framing := range []string{
		"Content-Length: 1\r\nContent-Length: 1\r\n",
		"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
		"Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n",
		"Transfer-Encoding: chunked, chunked\r\n",
		"Content-Length: -1\r\n",
		"Content-Length: \u00a01000000\r\n",
		"Content-Length: 1000000\r\r\n",
		"Transfer-Encoding: \u00a0chunked\r\n",
	} {
		t.Run(framing, func(t *testing.T) {
			h := newMetadataEngine(t, 80)
			h.send(t, false, []byte("GET /anchor HTTP/1.1\r\n\r\n"))
			h.send(t, false, []byte("POST /bad HTTP/1.1\r\n"+framing+"\r\n"))
			for i := 0; i < 100; i++ {
				h.send(t, false, []byte("POST /still-bad HTTP/1.1\r\n"+framing+"\r\n"))
			}
			h.want(t, "http", map[string]int{"request": 1, "malformed": 1})
			h.send(t, false, []byte("GET /after HTTP/1.1\r\n\r\n"))
			h.want(t, "http", map[string]int{"request": 2, "malformed": 1})
		})
	}
}

func TestHTTPLegacyEngineReassemblyLossRecovery(t *testing.T) {
	for _, anchored := range []bool{false, true} {
		t.Run(fmt.Sprint(anchored), func(t *testing.T) {
			h := newMetadataEngine(t, 80)
			counts := map[string]int{}
			if anchored {
				h.send(t, false, []byte("GET /anchor HTTP/1.1\r\n\r\n"))
				counts["request"] = 1
				counts["malformed"] = 1
			}
			for i := 0; i < 100; i++ {
				h.send(t, false, []byte(strings.Repeat("x", 30000)))
				h.send(t, false, []byte(strings.Repeat("y", 40000)))
			}
			h.want(t, "http", counts)
			h.send(t, false, []byte("GET /after HTTP/1.1\r\n\r\n"))
			counts["request"]++
			h.want(t, "http", counts)
		})
	}
}
