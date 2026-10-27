// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// pathOrigin answers every request with its path as the body.
func pathOrigin(t *testing.T, log *bodyLog) *origin {
	return httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		log.record(r, body, nil)
		_, _ = io.WriteString(w, "path="+r.URL.Path)
	}))
}

func TestKeepAliveThreeTransactions(t *testing.T) {
	log := &bodyLog{}
	o := pathOrigin(t, log)
	g := startGate(t, o, nil)
	c := g.client()
	for i := 1; i <= 3; i++ {
		path := fmt.Sprintf("/t%d", i)
		body := pattern(100_000*i, uint64(i))
		c.write(requestCL("POST", path, "", body))
		resp, rb := c.response("POST")
		if resp.StatusCode != 200 || string(rb) != "path="+path {
			t.Fatalf("transaction %d: status %d body %q", i, resp.StatusCode, rb)
		}
		up := g.events.next(t)
		expectEvent(t, up, avscan.Upload, avscan.Clean, "", avscan.Deliver)
		down := g.events.next(t)
		expectEvent(t, down, avscan.Download, avscan.Clean, "", avscan.Deliver)
		if up.Target != path || down.Target != path || up.Size != int64(len(body)) {
			t.Fatalf("events %+v %+v", up, down)
		}
	}
	entries := log.list()
	if len(entries) != 3 || o.rec.connections() != 1 {
		t.Fatalf("origin saw %d requests over %d connections", len(entries), o.rec.connections())
	}
	for i, e := range entries {
		if !bytes.Equal(e.body, pattern(100_000*(i+1), uint64(i+1))) {
			t.Fatalf("transaction %d body differs", i+1)
		}
	}
}

func TestPipelinedRequests(t *testing.T) {
	log := &bodyLog{}
	o := pathOrigin(t, log)
	g := startGate(t, o, nil)
	c := g.client()
	var both bytes.Buffer
	both.Write(requestCL("POST", "/first", "", pattern(50_000, 11)))
	both.Write(getRequest("/second", ""))
	c.write(both.Bytes())
	for _, want := range []string{"path=/first", "path=/second"} {
		resp, rb := c.response("GET")
		if resp.StatusCode != 200 || string(rb) != want {
			t.Fatalf("status %d body %q, want %q", resp.StatusCode, rb, want)
		}
	}
	if entries := log.list(); len(entries) != 2 || entries[0].path != "/first" || entries[1].path != "/second" {
		t.Fatalf("origin requests %+v", entries)
	}
	if o.rec.connections() != 1 {
		t.Fatalf("origin connections %d", o.rec.connections())
	}
}

func TestPipelinedBytesDiscardedOnBlock(t *testing.T) {
	log := &bodyLog{}
	o := pathOrigin(t, log)
	g := startGate(t, o, nil)
	c := g.client()
	var both bytes.Buffer
	both.Write(requestCL("POST", "/bad", "", []byte(infectedMarker)))
	both.Write(getRequest("/never", ""))
	c.write(both.Bytes())
	resp, _ := c.response("POST")
	if resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	c.expectEOF()
	if o.rec.connections() != 0 {
		t.Fatalf("origin connections %d after block", o.rec.connections())
	}
}

func TestHTTP10DefaultsToClose(t *testing.T) {
	log := &bodyLog{}
	o := pathOrigin(t, log)
	g := startGate(t, o, nil)
	c := g.client()
	c.write([]byte("GET /ten HTTP/1.0\r\nHost: origin.test\r\n\r\n"))
	resp, rb := c.response("GET")
	if resp.StatusCode != 200 || string(rb) != "path=/ten" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	c.expectEOF()
}

func TestConnectionCloseHonoured(t *testing.T) {
	log := &bodyLog{}
	o := pathOrigin(t, log)
	g := startGate(t, o, nil)
	c := g.client()
	c.write(getRequest("/close", "Connection: close\r\n"))
	resp, rb := c.response("GET")
	if resp.StatusCode != 200 || string(rb) != "path=/close" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	c.expectEOF()
}

// serveOneRaw answers one request on c with a Content-Length body.
func serveOneRaw(c net.Conn, body string) error {
	head, br, err := readRequestHead(c)
	if err != nil {
		return err
	}
	if _, err := readFullBody(head, br); err != nil {
		return err
	}
	_, err = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	return err
}

func TestOriginIdleCloseThenSecondRequest(t *testing.T) {
	o := rawOrigin(t, func(c net.Conn, n int) {
		if err := serveOneRaw(c, fmt.Sprintf("conn%d", n)); err != nil {
			return
		}
		// Close the keep-alive connection while it idles, as origins do.
		time.Sleep(50 * time.Millisecond)
	})
	g := startGate(t, o, nil)
	c := g.client()
	c.write(getRequest("/one", ""))
	if _, rb := c.response("GET"); string(rb) != "conn1" {
		t.Fatalf("first body %q", rb)
	}
	time.Sleep(300 * time.Millisecond)
	c.write(getRequest("/two", ""))
	if _, rb := c.response("GET"); string(rb) != "conn2" {
		t.Fatalf("second body %q", rb)
	}
	if o.rec.connections() != 2 {
		t.Fatalf("origin connections %d", o.rec.connections())
	}
}

func TestOriginClosesOnReusedRequestIsRetried(t *testing.T) {
	o := rawOrigin(t, func(c net.Conn, n int) {
		if err := serveOneRaw(c, fmt.Sprintf("conn%d", n)); err != nil {
			return
		}
		if n == 1 {
			// Read the next request and close without answering: the race
			// where the origin gives up on the idle connection as the
			// request arrives.
			_, _, _ = readRequestHead(c)
			return
		}
		_ = serveOneRaw(c, "conn1-second")
	})
	g := startGate(t, o, nil)
	c := g.client()
	c.write(getRequest("/one", ""))
	if _, rb := c.response("GET"); string(rb) != "conn1" {
		t.Fatalf("first body %q", rb)
	}
	c.write(getRequest("/two", ""))
	if _, rb := c.response("GET"); string(rb) != "conn2" {
		t.Fatalf("second body %q", rb)
	}
	if o.rec.connections() != 2 {
		t.Fatalf("origin connections %d", o.rec.connections())
	}
}

func TestBodylessResponsesKeepConnection(t *testing.T) {
	responses := []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
		"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n",
		"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	}
	o := rawOrigin(t, func(c net.Conn, _ int) {
		br := bufio.NewReader(c)
		for _, r := range responses {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := readHead(br); err != nil {
				return
			}
			if _, err := io.WriteString(c, r); err != nil {
				return
			}
		}
	})
	g := startGate(t, o, nil)
	c := g.client()
	c.write([]byte("HEAD /head HTTP/1.1\r\nHost: origin.test\r\n\r\n"))
	resp, _ := c.response("HEAD")
	if resp.StatusCode != 200 || resp.ContentLength != 100 {
		t.Fatalf("HEAD response %+v", resp)
	}
	c.write(getRequest("/204", ""))
	if resp, _ := c.response("GET"); resp.StatusCode != 204 {
		t.Fatalf("204 response %+v", resp)
	}
	c.write(getRequest("/304", ""))
	if resp, _ := c.response("GET"); resp.StatusCode != 304 {
		t.Fatalf("304 response %+v", resp)
	}
	c.write(getRequest("/ok", ""))
	if resp, rb := c.response("GET"); resp.StatusCode != 200 || string(rb) != "ok" {
		t.Fatalf("final response %+v %q", resp, rb)
	}
	if o.rec.connections() != 1 {
		t.Fatalf("origin connections %d", o.rec.connections())
	}
	// Only the final response carried a body, so only it was an object.
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Download, avscan.Clean, "", avscan.Deliver)
	if ev.Target != "/ok" || ev.Size != 2 {
		t.Fatalf("event %+v", ev)
	}
	g.events.expectNone(t, 50*time.Millisecond)
}

func TestMultipleInterimResponsesRelayed(t *testing.T) {
	o := rawOrigin(t, func(c net.Conn, _ int) {
		if _, _, err := readRequestHead(c); err != nil {
			return
		}
		for range 3 {
			_, _ = io.WriteString(c, "HTTP/1.1 102 Processing\r\n\r\n")
		}
		_, _ = io.WriteString(c, "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n")
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal")
	})
	g := startGate(t, o, nil)
	c := g.client()
	c.write(getRequest("/interim", ""))
	var statuses []int
	for {
		resp, rb := c.response("GET")
		statuses = append(statuses, resp.StatusCode)
		if resp.StatusCode >= 200 {
			if string(rb) != "final" {
				t.Fatalf("final body %q", rb)
			}
			break
		}
	}
	if fmt.Sprint(statuses) != "[102 102 102 103 200]" {
		t.Fatalf("statuses %v", statuses)
	}
	if !bytes.Contains(c.rec.bytes(), []byte("Link: </style.css>; rel=preload")) {
		t.Fatal("103 head not relayed verbatim")
	}
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Download, avscan.Clean, "", avscan.Deliver)
}

// An HTTP/1.0 client would take a relayed 1xx for the final response, so
// interim responses are dropped for it.
func TestInterimResponsesNotRelayedToHTTP10(t *testing.T) {
	o := rawOrigin(t, func(c net.Conn, _ int) {
		if _, _, err := readRequestHead(c); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n")
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal")
	})
	g := startGate(t, o, nil)
	c := g.client()
	c.write([]byte("GET /interim HTTP/1.0\r\nHost: origin.test\r\n\r\n"))
	resp, rb := c.response("GET")
	if resp.StatusCode != 200 || string(rb) != "final" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	c.expectEOF()
	if raw := c.rec.bytes(); bytes.Contains(raw, []byte(" 102 ")) || bytes.Contains(raw, []byte(" 103 ")) {
		t.Fatalf("1xx relayed to an HTTP/1.0 client: %q", raw)
	}
	expectEvent(t, g.events.next(t), avscan.Download, avscan.Clean, "", avscan.Deliver)
}

func TestTooManyInterimResponsesUnsupported(t *testing.T) {
	for _, policy := range []avscan.FailPolicy{avscan.FailClosed, avscan.FailOpen} {
		t.Run(string(policy), func(t *testing.T) {
			o := rawOrigin(t, func(c net.Conn, _ int) {
				if _, _, err := readRequestHead(c); err != nil {
					return
				}
				for range 17 {
					_, _ = io.WriteString(c, "HTTP/1.1 102 Processing\r\n\r\n")
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal")
			})
			g := startGate(t, o, func(s *Settings) { s.FailPolicy = policy })
			c := g.client()
			c.write(getRequest("/interim", ""))
			var statuses []int
			for {
				resp, rb := c.response("GET")
				statuses = append(statuses, resp.StatusCode)
				if resp.StatusCode >= 200 {
					want := "final"
					if policy == avscan.FailClosed {
						want = "containd: unsupported HTTP response: more than 16 interim responses"
					}
					if !strings.Contains(string(rb), want) {
						t.Fatalf("final body %q", rb)
					}
					break
				}
			}
			final := statuses[len(statuses)-1]
			if (policy == avscan.FailClosed && final != 502) || (policy == avscan.FailOpen && final != 200) {
				t.Fatalf("statuses %v", statuses)
			}
			c.expectEOF()
			ev := g.events.next(t)
			want := avscan.Block
			if policy == avscan.FailOpen {
				want = avscan.PassUnscanned
			}
			expectEvent(t, ev, avscan.Download, avscan.Unscanned, avscan.ReasonUnsupported, want)
		})
	}
}

func TestEarlyFinalResponseDuringUpload(t *testing.T) {
	o := rawOrigin(t, func(c net.Conn, _ int) {
		if _, _, err := readRequestHead(c); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 3\r\n\r\nbig")
		// Stop reading; wait for the gate to close the connection.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(io.Discard, c)
	})
	g := startGate(t, o, func(s *Settings) { s.ScanUploads = false })
	c := g.client()
	body := pattern(8<<20, 21)
	head := requestCL("POST", "/big", "", nil)
	c.write(head[:len(head)-len("Content-Length: 0\r\n\r\n")])
	c.write([]byte(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.conn.Write(body)
	}()
	resp, rb := c.response("POST")
	if resp.StatusCode != 413 || string(rb) != "big" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	c.expectClosed()
	<-done
	if n := len(o.rec.bytes()); n >= len(body) {
		t.Fatalf("origin received the whole body (%d bytes) despite its early response", n)
	}
}
