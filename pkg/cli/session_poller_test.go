// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func awaitSessionStatus(t *testing.T, p *SessionStatusPoller, want func(SessionStatus) bool) SessionStatus {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		status := p.Snapshot()
		if want(status) {
			return status
		}
		select {
		case <-p.Updates():
		case <-timer.C:
			t.Fatalf("status never arrived: %+v", p.Snapshot())
		}
	}
}

func sessionResponse(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{"X-Auth-Token": {"status-token"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestSessionStatusRequestHasShortDeadline(t *testing.T) {
	api := &API{BaseURL: "http://management", Client: sessionHTTP(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > sessionStatusTimeout || sessionStatusTimeout > 250*time.Millisecond {
			t.Error("status request must have a deadline no longer than 250 ms")
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	status := api.SessionStatus(context.Background())
	if status.Known || !strings.Contains(status.Error, "deadline exceeded") {
		t.Fatalf("timed-out status claimed authority: %+v", status)
	}
}

func TestSessionPollerInvalidatesOutstandingResponses(t *testing.T) {
	started := make(chan string, 4)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var calls atomic.Int32
	api := &API{BaseURL: "http://management", Token: "command-token", Client: sessionHTTP(func(r *http.Request) (*http.Response, error) {
		call := calls.Add(1)
		started <- r.Header.Get("Authorization")
		if call == 1 {
			// Hold the old response until after invalidation, even on a
			// heavily loaded runner. Deadline enforcement has its own test.
			<-release
			return sessionResponse(200, `{"changed":false}`), nil
		}
		return sessionResponse(200, `{"changed":true,"pendingConfirm":{"deadline":"2030-01-01T00:00:00Z"}}`), nil
	})}
	p := newSessionStatusPoller(context.Background(), api, nil, func() {})
	defer p.Close()
	defer unblock()
	if got := <-started; got != "Bearer command-token" {
		t.Fatal(got)
	}
	// Neither entering a command nor a post-mutation refresh waits for HTTP.
	if status := p.Snapshot(); status.Known || !strings.Contains(status.Prompt("admin"), "(config?)") {
		t.Fatal("in-flight status claimed a clean candidate")
	}
	api.Token = "new-command-token"
	p.Refresh(api)
	if p.Snapshot().Known {
		t.Fatal("mutation did not immediately invalidate status")
	}
	unblock()
	status := awaitSessionStatus(t, p, func(s SessionStatus) bool { return s.Known })
	if !status.Changed || status.Deadline == "" || api.Token != "new-command-token" {
		t.Fatalf("stale response or shared token mutation: %+v", status)
	}
	if got := <-started; got != "Bearer new-command-token" {
		t.Fatal("post-command refresh did not use current credentials")
	}
	p.SyncToken(api)
	if api.Token != "status-token" {
		t.Fatal("idle credential renewal was not adopted before the next command")
	}
}

func TestSessionPollerIdleFailureAndRecovery(t *testing.T) {
	var calls atomic.Int32
	api := &API{BaseURL: "http://management", Client: sessionHTTP(func(*http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return sessionResponse(200, `{"changed":false}`), nil
		case 2:
			return sessionResponse(503, `{}`), nil
		default:
			return sessionResponse(200, `{"changed":true}`), nil
		}
	})}
	ticks := make(chan time.Time)
	p := newSessionStatusPoller(context.Background(), api, ticks, func() {})
	defer p.Close()
	awaitSessionStatus(t, p, func(s SessionStatus) bool { return s.Known && !s.Changed })
	ticks <- time.Now()
	failed := awaitSessionStatus(t, p, func(s SessionStatus) bool { return strings.Contains(s.Error, "503") })
	if failed.Known || !strings.Contains(failed.Prompt("admin"), "(config?)") {
		t.Fatal("idle failure kept an old clean-state claim")
	}
	ticks <- time.Now()
	awaitSessionStatus(t, p, func(s SessionStatus) bool { return s.Known && s.Changed })
}

func TestSessionPollerCloseCancelsInFlightRequest(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	api := &API{BaseURL: "http://management", Client: sessionHTTP(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		close(stopped)
		return nil, errors.New("cancelled status request")
	})}
	p := newSessionStatusPoller(context.Background(), api, nil, func() {})
	<-started
	p.Close()
	select {
	case <-stopped:
	default:
		t.Fatal("status worker outlived its terminal")
	}
}
