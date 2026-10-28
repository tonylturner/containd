// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

func expectHead(path string, n int) []byte {
	return []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: origin.test\r\nExpect: 100-continue\r\nContent-Length: %d\r\n\r\n", path, n))
}

func TestExpectHeldUploadAnsweredByGate(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, nil)
	c := g.client()
	body := pattern(200_000, 31)
	c.write(expectHead("/expect", len(body)))
	resp, _ := c.response("POST")
	if resp.StatusCode != 100 {
		t.Fatalf("expected 100 Continue, got %d", resp.StatusCode)
	}
	if o.rec.connections() != 0 {
		t.Fatal("origin was dialled before the body was held")
	}
	c.write(body)
	resp, rb := c.response("POST")
	if resp.StatusCode != 200 || string(rb) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	got := log.list()
	if len(got) != 1 || !bytes.Equal(got[0].body, body) {
		t.Fatal("origin did not receive the identical body")
	}
	if _, ok := got[0].header["Expect"]; ok {
		t.Fatal("Expect forwarded although the gate answered it")
	}
	if bytes.Contains(o.rec.bytes(), []byte("Expect:")) {
		t.Fatal("raw Expect header reached the origin")
	}
	if n := bytes.Count(c.rec.bytes(), []byte(" 100 Continue")); n != 1 {
		t.Fatalf("client saw %d 100 Continue responses", n)
	}
	calls := g.scanner.scanCalls()
	if len(calls) != 2 || calls[0].obj.Direction != avscan.Upload || bytes.Contains(calls[0].obj.RequestHead, []byte("Expect")) {
		t.Fatalf("scanner saw %d calls, first head %q", len(calls), calls[0].obj.RequestHead)
	}
}

func TestExpectEarlyRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		adjust func(g *gate, s *Settings)
		length int
		reason avscan.Reason
	}{
		{"not-ready", func(g *gate, s *Settings) { g.scanner.setNotReady("clamd down") }, 1000, avscan.ReasonNotReady},
		{"oversized", func(g *gate, s *Settings) {}, 2 << 20, avscan.ReasonOversized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &bodyLog{}
			o := echoOrigin(t, log)
			g := startGate(t, o, func(s *Settings) { s.MaxObjectBytes = 1 << 20 })
			tc.adjust(g, nil)
			c := g.client()
			c.write(expectHead("/refused", tc.length))
			resp, rb := c.response("POST")
			if resp.StatusCode != 403 || !strings.Contains(string(rb), string(tc.reason)) {
				t.Fatalf("status %d body %q", resp.StatusCode, rb)
			}
			c.expectEOF()
			if o.rec.connections() != 0 || len(g.scanner.scanCalls()) != 0 {
				t.Fatal("origin or scanner reached for an early refusal")
			}
			ev := g.events.next(t)
			expectEvent(t, ev, avscan.Upload, avscan.Unscanned, tc.reason, avscan.Block)
			if ev.Backend != "gate" || ev.Size != int64(tc.length) {
				t.Fatalf("event %+v", ev)
			}
		})
	}
}

func TestExpectFailOpenForwardsUnheld(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.FailPolicy = avscan.FailOpen })
	g.scanner.setNotReady("clamd down")
	c := g.client()
	body := pattern(100_000, 32)
	c.write(expectHead("/open", len(body)))
	resp, _ := c.response("POST")
	if resp.StatusCode != 100 {
		t.Fatalf("expected the origin's 100 Continue, got %d", resp.StatusCode)
	}
	c.write(body)
	resp, rb := c.response("POST")
	if resp.StatusCode != 200 || string(rb) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	if !bytes.Contains(o.rec.bytes(), []byte("Expect: 100-continue\r\n")) {
		t.Fatal("Expect was not forwarded unchanged")
	}
	if got := log.list(); len(got) != 1 || !bytes.Equal(got[0].body, body) {
		t.Fatal("origin did not receive the identical body")
	}
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonNotReady, avscan.PassUnscanned)
	if ev.Size != int64(len(body)) || ev.SHA256 != "" || !ev.SHA256Partial {
		t.Fatalf("event %+v", ev)
	}
}

func TestExpectOtherValueRefused(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, nil)
	c := g.client()
	c.write([]byte("POST /x HTTP/1.1\r\nHost: origin.test\r\nExpect: 200-ok\r\nContent-Length: 3\r\n\r\n"))
	resp, _ := c.response("POST")
	if resp.StatusCode != 417 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	c.expectEOF()
	if o.rec.connections() != 0 {
		t.Fatal("origin dialled for a refused expectation")
	}
}

func TestUnselectedExpectIsOriginsBusiness(t *testing.T) {
	o := httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := readAllBody(r)
		fmt.Fprintf(w, "%d", len(b))
	}))
	g := startGate(t, o, func(s *Settings) { s.ScanUploads, s.ScanDownloads = false, false })
	c := g.client()
	body := pattern(5000, 33)
	c.write(expectHead("/plain", len(body)))
	resp, _ := c.response("POST")
	if resp.StatusCode != 100 {
		t.Fatalf("expected relayed 100, got %d", resp.StatusCode)
	}
	c.write(body)
	resp, rb := c.response("POST")
	if resp.StatusCode != 200 || string(rb) != "5000" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	g.events.expectNone(t, 50*time.Millisecond)
}
