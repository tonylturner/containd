// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// A URL whose download was Infected is refused for the TTL, Range
// requests included, before the origin is contacted; other URLs and the
// same URL after the TTL are served and scanned as usual.
func TestBlockedURLRefusedWithinTTL(t *testing.T) {
	body := pattern(4096, 301)
	var served atomic.Int32
	o := httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if served.Add(1) == 1 {
			_, _ = w.Write(append(body, []byte(infectedMarker)...))
			return
		}
		_, _ = w.Write(body)
	}))
	ttl := 400 * time.Millisecond
	g := startGate(t, o, func(s *Settings) { s.BlockedURLTTL = ttl; s.BlockedURLEntries = 8 })
	c := g.client()
	c.write(getRequest("/evil?x=1", ""))
	resp, _ := c.response("GET")
	if resp.StatusCode != 403 {
		t.Fatalf("infected download: status %d", resp.StatusCode)
	}
	c.expectEOF()
	expectEvent(t, g.events.next(t), avscan.Download, avscan.Infected, "", avscan.Block)
	blockedAt := time.Now()

	for _, target := range []string{"/evil?x=1", "http://ORIGIN.test/evil?x=1"} {
		c = g.client()
		c.write([]byte("GET " + target + " HTTP/1.1\r\nHost: origin.test\r\nRange: bytes=2048-\r\n\r\n"))
		resp, rb := c.response("GET")
		if resp.StatusCode != 403 || !strings.Contains(string(rb), "recently infected URL") {
			t.Fatalf("%s: status %d body %q", target, resp.StatusCode, rb)
		}
		c.expectEOF()
		ev := g.events.next(t)
		expectEvent(t, ev, avscan.Download, avscan.Infected, ReasonRecentlyInfected, avscan.Block)
		if ev.Signature != testSignature || ev.Backend != "gate" || ev.Detail != recentlyInfectedDetail || !strings.EqualFold(ev.Host, "origin.test") {
			t.Fatalf("event %+v", ev)
		}
	}
	if served.Load() != 1 || len(g.scanner.scanCalls()) != 1 {
		t.Fatalf("refused requests reached the origin (%d served) or the scanner (%d calls)", served.Load(), len(g.scanner.scanCalls()))
	}

	c = g.client()
	c.write(getRequest("/evil?x=2", ""))
	resp, rb := c.response("GET")
	if resp.StatusCode != 200 || !bytes.Equal(rb, body) {
		t.Fatalf("other query: status %d, %d bytes", resp.StatusCode, len(rb))
	}
	expectEvent(t, g.events.next(t), avscan.Download, avscan.Clean, "", avscan.Deliver)

	time.Sleep(time.Until(blockedAt.Add(ttl)))
	c = g.client()
	c.write(getRequest("/evil?x=1", ""))
	resp, rb = c.response("GET")
	if resp.StatusCode != 200 || !bytes.Equal(rb, body) {
		t.Fatalf("after the TTL: status %d, %d bytes", resp.StatusCode, len(rb))
	}
	expectEvent(t, g.events.next(t), avscan.Download, avscan.Clean, "", avscan.Deliver)
	if served.Load() != 3 || len(g.scanner.scanCalls()) != 3 {
		t.Fatalf("origin served %d, scanner calls %d", served.Load(), len(g.scanner.scanCalls()))
	}
}

func TestBlockedURLsBoundAndExpiry(t *testing.T) {
	b := newBlockedURLs()
	key := func(path string) urlKey {
		return urlKey{client: netip.MustParseAddr("10.0.0.1"), server: netip.MustParseAddrPort("10.0.0.2:80"), host: "h", path: path}
	}
	b.add(key("/a"), "Sig.A", time.Minute, 2)
	b.add(key("/b"), "Sig.B", time.Minute, 2)
	b.add(key("/a"), "Sig.A2", time.Minute, 2)
	b.add(key("/c"), "Sig.C", time.Minute, 2)
	if b.len() != 2 {
		t.Fatalf("%d entries over a bound of 2", b.len())
	}
	if _, ok := b.lookup(key("/b")); ok {
		t.Fatal("the oldest entry survived the bound")
	}
	if sig, ok := b.lookup(key("/a")); !ok || sig != "Sig.A2" {
		t.Fatalf("refreshed entry: %q %v", sig, ok)
	}
	if _, ok := b.lookup(key("/c")); !ok {
		t.Fatal("newest entry missing")
	}
	b.add(key("/d"), "Sig.D", time.Nanosecond, 2)
	time.Sleep(time.Millisecond)
	if _, ok := b.lookup(key("/d")); ok || b.len() != 1 {
		t.Fatalf("expired entry still present (%d entries)", b.len())
	}
	b.add(key("/e"), "", time.Minute, 1)
	if b.len() != 1 {
		t.Fatalf("%d entries over a bound of 1", b.len())
	}
}

func TestRequestPath(t *testing.T) {
	for target, want := range map[string]string{
		"/p?q=1":                     "/p?q=1",
		"http://h:8080/p?q=1":        "/p?q=1",
		"http://h":                   "/",
		"http://h?q":                 "?q",
		"*":                          "*",
		"HTTPS://x.example/a/b#frag": "/a/b#frag",
	} {
		if got := requestPath(target); got != want {
			t.Errorf("requestPath(%q) = %q, want %q", target, got, want)
		}
	}
}
