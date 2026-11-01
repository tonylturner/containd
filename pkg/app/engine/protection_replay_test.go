// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
)

func TestProtectionReplayWindowExceedsRequestTimeouts(t *testing.T) {
	client := engineapi.NewHTTPClient("http://127.0.0.1:8081")
	server := engineServer("", nil, nil)
	budget := client.Client.Timeout + server.ReadHeaderTimeout + server.ReadTimeout
	if client.Client.Timeout <= 0 || server.ReadHeaderTimeout <= 0 || applyReplayWindow <= budget {
		t.Fatalf("replay window %s must exceed request timeout budget %s", applyReplayWindow, budget)
	}
}

func TestProtectionReplayWindow(t *testing.T) {
	c := testProtectionCoordinator(t, &coordinatorFake{})
	now := time.Now()
	c.now = func() time.Time { return now }
	calls := 0
	h := c.admit(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(200) })
	post := func(id string, want int) {
		t.Helper()
		if w := coordinatedPost(h, id, `{}`); w.Code != want {
			t.Fatalf("%q: %d %s; want %d", id, w.Code, w.Body, want)
		}
	}
	post("z-opaque", 200)
	now = now.Add(2 * applyReplayWindow)
	post("z-opaque", 200) // current IDs never expire
	post("a-opaque", 200) // no lexical/clock ordering of IDs
	if len(c.seen) != 1 {
		t.Fatalf("history must contain only the superseded ID: %v", c.seen)
	}
	now = now.Add(applyReplayWindow - time.Nanosecond)
	post("z-opaque", 409)
	if calls != 3 {
		t.Fatal("stale request had side effects")
	}
	now = now.Add(time.Nanosecond)
	post("third", 200)
	if _, retained := c.seen["z-opaque"]; retained {
		t.Fatal("expired superseded ID retained")
	}
	post("z-opaque", 200) // outside the documented replay window
}

func TestProtectionReplayExpiredAdmission(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		c := testProtectionCoordinator(t, &coordinatorFake{})
		now := time.Now()
		c.now = func() time.Time {
			defer func() { now = now.Add(applyReplayWindow) }()
			return now
		}
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set(applyIDHeader, "old")
		if canceled {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			r = r.WithContext(ctx)
			c.now = time.Now
		}
		w := httptest.NewRecorder()
		c.admit(func(http.ResponseWriter, *http.Request) { t.Fatal("expired request admitted") })(w, r)
		if w.Code != http.StatusRequestTimeout || c.current != "" {
			t.Fatalf("expired request: %d; current=%q", w.Code, c.current)
		}
	}
}
