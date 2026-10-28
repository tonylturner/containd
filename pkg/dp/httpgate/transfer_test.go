// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

const threeMiB = 3 << 20

func TestCleanUploadKeepsFraming(t *testing.T) {
	body := pattern(threeMiB, 1)
	for _, tc := range []struct {
		name    string
		req     []byte
		framing string
		rawMark string
	}{
		{"content-length", requestCL("POST", "/up", "", body), fmt.Sprintf("length=%d", threeMiB), "Content-Length: 3145728\r\n"},
		{"chunked", requestChunked("POST", "/up", "", body, 7919), "chunked", "\r\n0\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &bodyLog{}
			o := echoOrigin(t, log)
			g := startGate(t, o, nil)
			c := g.client()
			c.write(tc.req)
			resp, rb := c.response("POST")
			if resp.StatusCode != 200 || string(rb) != "ok" {
				t.Fatalf("status %d body %q", resp.StatusCode, rb)
			}
			got := log.list()
			if len(got) != 1 || !bytes.Equal(got[0].body, body) {
				t.Fatalf("origin received %d entries, identical=%v", len(got), len(got) == 1 && bytes.Equal(got[0].body, body))
			}
			if got[0].framing != tc.framing {
				t.Fatalf("origin framing %q, want %q", got[0].framing, tc.framing)
			}
			if !bytes.Contains(o.rec.bytes(), []byte(tc.rawMark)) {
				t.Fatalf("origin raw bytes lack %q", tc.rawMark)
			}
			ev := g.events.next(t)
			expectEvent(t, ev, avscan.Upload, avscan.Clean, "", avscan.Deliver)
			if ev.Size != threeMiB || ev.SHA256 != sha256hex(body) || ev.SHA256Partial || ev.Method != "POST" || ev.Target != "/up" || ev.Host != "origin.test" || ev.Backend != "fake" {
				t.Fatalf("event %+v", ev)
			}
			if o.rec.connections() != 1 {
				t.Fatalf("origin connections %d", o.rec.connections())
			}
		})
	}
}

func TestCleanDownloadKeepsFraming(t *testing.T) {
	body := pattern(threeMiB, 2)
	for _, tc := range []struct {
		name   string
		origin func(t *testing.T) *origin
		check  func(t *testing.T, resp *http.Response)
		closes bool
	}{
		{
			name: "content-length",
			origin: func(t *testing.T) *origin {
				return httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", fmt.Sprint(len(body)))
					_, _ = w.Write(body)
				}))
			},
			check: func(t *testing.T, resp *http.Response) {
				if resp.ContentLength != threeMiB || len(resp.TransferEncoding) != 0 {
					t.Fatalf("content-length %d transfer-encoding %v", resp.ContentLength, resp.TransferEncoding)
				}
			},
		},
		{
			name: "chunked",
			origin: func(t *testing.T) *origin {
				return httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for off := 0; off < len(body); off += 65536 {
						_, _ = w.Write(body[off:min(off+65536, len(body))])
						w.(http.Flusher).Flush()
					}
				}))
			},
			check: func(t *testing.T, resp *http.Response) {
				if strings.Join(resp.TransferEncoding, ",") != "chunked" {
					t.Fatalf("transfer-encoding %v", resp.TransferEncoding)
				}
			},
		},
		{
			name: "close-delimited",
			origin: func(t *testing.T) *origin {
				return rawOrigin(t, func(c net.Conn, _ int) {
					if _, _, err := readRequestHead(c); err != nil {
						return
					}
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"))
					_, _ = c.Write(body)
				})
			},
			check: func(t *testing.T, resp *http.Response) {
				if resp.ContentLength != -1 || len(resp.TransferEncoding) != 0 {
					t.Fatalf("content-length %d transfer-encoding %v", resp.ContentLength, resp.TransferEncoding)
				}
			},
			closes: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.origin(t)
			g := startGate(t, o, nil)
			c := g.client()
			c.write(getRequest("/down", ""))
			resp, rb := c.response("GET")
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if !bytes.Equal(rb, body) {
				t.Fatalf("client body differs (%d bytes, want %d)", len(rb), len(body))
			}
			tc.check(t, resp)
			ev := g.events.next(t)
			expectEvent(t, ev, avscan.Download, avscan.Clean, "", avscan.Deliver)
			if ev.Size != threeMiB || ev.SHA256 != sha256hex(body) || ev.Status != 200 || ev.Method != "GET" {
				t.Fatalf("event %+v", ev)
			}
			if tc.closes {
				c.expectEOF()
			}
		})
	}
}

func TestInfectedUploadNeverReachesOrigin(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, nil)
	release := g.scanner.holdScans()
	body := append(pattern(threeMiB, 3), []byte(infectedMarker)...)
	c := g.client()
	c.write(requestChunked("POST", "/malware", "", body, 4096))
	g.scanner.waitScanStarted(t)
	c.expectSilence(100 * time.Millisecond)
	if n := o.rec.connections(); n != 0 {
		t.Fatalf("origin accepted %d connections before the verdict", n)
	}
	release()
	resp, rb := c.response("POST")
	if resp.StatusCode != 403 || !resp.Close || resp.ContentLength != int64(len(rb)) {
		t.Fatalf("response %+v body %q", resp, rb)
	}
	if !strings.Contains(string(rb), "containd") || !strings.Contains(string(rb), testSignature) {
		t.Fatalf("403 body %q", rb)
	}
	c.expectEOF()
	if o.rec.connections() != 0 || len(o.rec.bytes()) != 0 {
		t.Fatalf("origin got %d connections, %d bytes", o.rec.connections(), len(o.rec.bytes()))
	}
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Upload, avscan.Infected, "", avscan.Block)
	if ev.Signature != testSignature || ev.Size != int64(len(body)) || ev.SHA256 != sha256hex(body) {
		t.Fatalf("event %+v", ev)
	}
}

func TestInfectedDownloadBlocked(t *testing.T) {
	body := append(pattern(threeMiB, 4), []byte(infectedMarker)...)
	o := httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Secret", "origin-header-must-not-leak")
		_, _ = w.Write(body)
	}))
	g := startGate(t, o, nil)
	release := g.scanner.holdScans()
	c := g.client()
	c.write(getRequest("/malware", ""))
	g.scanner.waitScanStarted(t)
	c.expectSilence(100 * time.Millisecond)
	release()
	resp, rb := c.response("GET")
	if resp.StatusCode != 403 || !strings.Contains(string(rb), testSignature) {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	c.expectEOF()
	raw := c.rec.bytes()
	if bytes.Contains(raw, []byte(infectedMarker)) || bytes.Contains(raw, []byte("origin-header-must-not-leak")) {
		t.Fatal("original object leaked to the client")
	}
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Download, avscan.Infected, "", avscan.Block)
	if ev.Status != 200 || ev.Size != int64(len(body)) {
		t.Fatalf("event %+v", ev)
	}
}

func TestCleanTransfersHoldUntilVerdict(t *testing.T) {
	body := pattern(256<<10, 5)
	log := &bodyLog{}
	o := httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			b, _ := readAllBody(r)
			log.record(r, b, nil)
		}
		_, _ = w.Write(body)
	}))
	g := startGate(t, o, nil)
	releaseUpload := g.scanner.holdScans()
	c := g.client()
	c.write(requestCL("POST", "/hold", "", body))
	g.scanner.waitScanStarted(t)
	c.expectSilence(100 * time.Millisecond)
	if o.rec.connections() != 0 {
		t.Fatalf("origin accepted %d connections before the upload verdict", o.rec.connections())
	}
	// A separate latch for the download, installed before the upload is
	// released so the response is really held until it is released.
	releaseDownload := g.scanner.holdScans()
	releaseUpload()
	g.scanner.waitScanStarted(t)
	c.expectSilence(100 * time.Millisecond)
	releaseDownload()
	resp, rb := c.response("POST")
	if resp.StatusCode != 200 || !bytes.Equal(rb, body) {
		t.Fatalf("status %d, identical=%v", resp.StatusCode, bytes.Equal(rb, body))
	}
	if got := log.list(); len(got) != 1 || !bytes.Equal(got[0].body, body) {
		t.Fatal("origin did not receive the identical upload")
	}
}

func readAllBody(r *http.Request) ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(r.Body)
	return b.Bytes(), err
}
