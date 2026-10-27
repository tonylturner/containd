// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"context"
	"errors"
	"math"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

func TestUpdateMidFlightKeepsSnapshot(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.ScanDownloads = false })
	release := g.scanner.holdScans()
	g.scanner.setVerdict(func(avscan.Object, []byte) avscan.Result {
		return avscan.Result{Verdict: avscan.Unscanned, Reason: avscan.ReasonScannerError, Backend: "fake"}
	})
	c := g.client()
	c.write(requestCL("POST", "/inflight", "", pattern(500, 71)))
	g.scanner.waitScanStarted(t)
	open := testSettings(g.spoolDir)
	open.FailPolicy, open.ScanDownloads = avscan.FailOpen, false
	if err := g.srv.Update(open); err != nil {
		t.Fatal(err)
	}
	release()
	if resp, _ := c.response("POST"); resp.StatusCode != 403 {
		t.Fatalf("in-flight transaction used the new policy: status %d", resp.StatusCode)
	}
	expectEvent(t, g.events.next(t), avscan.Upload, avscan.Unscanned, avscan.ReasonScannerError, avscan.Block)
	c2 := g.client()
	c2.write(requestCL("POST", "/after", "", pattern(500, 72)))
	if resp, rb := c2.response("POST"); resp.StatusCode != 200 || string(rb) != "ok" {
		t.Fatalf("new transaction under fail-open: %d %q", resp.StatusCode, rb)
	}
	expectEvent(t, g.events.next(t), avscan.Upload, avscan.Unscanned, avscan.ReasonScannerError, avscan.PassUnscanned)
}

func TestInvalidUpdateRejected(t *testing.T) {
	g := startGate(t, &origin{rec: &recorder{}}, nil)
	before := g.srv.settings.Load()
	for name, mutate := range map[string]func(*Settings){
		"empty-policy":        func(s *Settings) { s.FailPolicy = "" },
		"unknown-policy":      func(s *Settings) { s.FailPolicy = "maybe" },
		"zero-max-object":     func(s *Settings) { s.MaxObjectBytes = 0 },
		"negative-threshold":  func(s *Settings) { s.MemoryThreshold = -1 },
		"zero-connections":    func(s *Settings) { s.MaxConnections = 0 },
		"zero-objects":        func(s *Settings) { s.MaxConcurrentObjects = 0 },
		"zero-idle":           func(s *Settings) { s.IdleTimeout = 0 },
		"zero-object-timeout": func(s *Settings) { s.ObjectTimeout = 0 },
		"zero-dial":           func(s *Settings) { s.DialTimeout = 0 },
		"zero-scan":           func(s *Settings) { s.ScanTimeout = 0 },
		"overflow-disk":       func(s *Settings) { s.MaxConcurrentObjects = 4; s.MaxObjectBytes = math.MaxInt64 / 2 },
		"overflow-memory":     func(s *Settings) { s.MaxConcurrentObjects = 4; s.MemoryThreshold = math.MaxInt64 / 2 },
	} {
		set := testSettings(g.spoolDir)
		mutate(&set)
		if err := g.srv.Update(set); err == nil {
			t.Errorf("%s: Update accepted invalid settings", name)
		}
		if g.srv.settings.Load() != before {
			t.Fatalf("%s: settings replaced after a rejected Update", name)
		}
	}
	set := testSettings("")
	if err := g.srv.Update(set); err != nil || g.srv.settings.Load().SpoolDir == "" {
		t.Fatalf("empty SpoolDir should default: %v", err)
	}
}

// The largest cap is accepted and handled without overflowing the
// spool's lookahead arithmetic.
func TestMaxIntObjectCapHandled(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) {
		s.ScanDownloads = false
		s.MaxConcurrentObjects, s.MaxObjectBytes = 1, math.MaxInt64
	})
	c := g.client()
	c.write(requestCL("POST", "/max", "", pattern(1000, 74)))
	resp, rb := c.response("POST")
	ev := g.events.next(t)
	if resp.StatusCode != 200 || string(rb) != "ok" {
		t.Fatalf("upload under MaxInt64 cap: %d %q (event %+v)", resp.StatusCode, rb, ev)
	}
	expectEvent(t, ev, avscan.Upload, avscan.Clean, "", avscan.Deliver)
}

func TestServeRequiresUpdateAndHooks(t *testing.T) {
	ln, _ := listenLoopback(t)
	s := &Server{}
	if err := s.Serve(ln); err == nil || !strings.Contains(err.Error(), "Update") {
		t.Fatalf("Serve without settings: %v", err)
	}
	ln2, _ := listenLoopback(t)
	if err := s.Update(testSettings(t.TempDir())); err != nil {
		t.Fatal(err)
	}
	if err := s.Serve(ln2); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("Serve without hooks: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownCancelsScansAndIsFinite(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.ScanTimeout = time.Minute })
	g.scanner.holdScans()
	c := g.client()
	c.write(requestCL("POST", "/stuck", "", pattern(100, 73)))
	g.scanner.waitScanStarted(t)
	start := time.Now()
	if err := g.shutdown(10 * time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("Shutdown took %v", took)
	}
	resp, rb := c.response("POST")
	if resp.StatusCode != 403 || !strings.Contains(string(rb), "timeout") {
		t.Fatalf("client got %d %q", resp.StatusCode, rb)
	}
	calls := g.scanner.scanCalls()
	if len(calls) != 1 || !errors.Is(calls[0].ctxErr, context.Canceled) {
		t.Fatalf("scan context: %+v", calls)
	}
	c2, err := net.Dial("tcp", g.addr.String())
	if err == nil {
		c2.Close()
		t.Fatal("listener still accepting after Shutdown")
	}
}

func TestShutdownClosesIdleConnectionsAtOnce(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.IdleTimeout = time.Minute })
	fresh := g.client()
	keptAlive := g.client()
	keptAlive.write(getRequest("/one", ""))
	if resp, _ := keptAlive.response("GET"); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	eventually(t, "connections tracked", func() bool { return g.srv.activeConns.Load() == 2 })
	start := time.Now()
	if err := g.shutdown(5 * time.Second); err != nil {
		t.Fatalf("Shutdown returned %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Shutdown took %v for idle connections", took)
	}
	fresh.expectEOF()
	keptAlive.expectEOF()
}

func TestShutdownForcesActiveConnectionsAtDeadline(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.ScanUploads = false; s.IdleTimeout = time.Minute })
	c := g.client()
	// A request body still streaming keeps the connection active.
	c.write([]byte("POST /slow HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 100\r\n\r\npartial"))
	eventually(t, "origin to see the request", func() bool { return len(o.rec.bytes()) > 0 })
	start := time.Now()
	err := g.shutdown(200 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown returned %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Shutdown took %v", took)
	}
	c.expectClosed()
}

func TestNoGoroutineLeakAndCleanSpool(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	runtime.GC()
	baseline := runtime.NumGoroutine()
	g := startGate(t, o, func(s *Settings) { s.MemoryThreshold = 4096 })
	c := g.client()
	for i := range 3 {
		c.write(requestCL("POST", "/leak", "", pattern(threeMiB, uint64(80+i))))
		if resp, _ := c.response("POST"); resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	// An upload still held when Shutdown runs.
	g.scanner.holdScans()
	c2 := g.client()
	c2.write(requestCL("POST", "/held", "", pattern(100_000, 90)))
	g.scanner.waitScanStarted(t)
	if err := g.shutdown(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	c.conn.Close()
	c2.conn.Close()
	eventually(t, "goroutines to return to baseline", func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= baseline
	})
}

func TestSpoolSlotHeldThroughDelivery(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.ScanDownloads = false })
	release := g.scanner.holdScans()
	c := g.client()
	c.write(requestCL("POST", "/slot", "", pattern(100, 91)))
	g.scanner.waitScanStarted(t)
	if n := g.srv.heldObjects.Load(); n != 1 {
		t.Fatalf("held objects %d during scan", n)
	}
	release()
	if resp, _ := c.response("POST"); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	eventually(t, "slot release", func() bool { return g.srv.heldObjects.Load() == 0 })
}

// With one object slot and both directions selected, a held upload must
// free its slot once sent so the response can be held with it.
func TestUploadSlotFreedBeforeResponse(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.MaxConcurrentObjects = 1 })
	c := g.client()
	c.write(requestCL("POST", "/slot", "", pattern(100, 93)))
	resp, rb := c.response("POST")
	if resp.StatusCode != 200 || string(rb) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, rb)
	}
	expectEvent(t, g.events.next(t), avscan.Upload, avscan.Clean, "", avscan.Deliver)
	expectEvent(t, g.events.next(t), avscan.Download, avscan.Clean, "", avscan.Deliver)
	eventually(t, "slot release", func() bool { return g.srv.heldObjects.Load() == 0 })
}

func TestClientCloseDuringScanCancelsIt(t *testing.T) {
	log := &bodyLog{}
	o := echoOrigin(t, log)
	g := startGate(t, o, func(s *Settings) { s.ScanTimeout = time.Minute; s.ScanDownloads = false })
	g.scanner.holdScans()
	c := g.client()
	c.write(requestCL("POST", "/gone", "", pattern(100, 92)))
	g.scanner.waitScanStarted(t)
	c.conn.Close()
	ev := g.events.next(t)
	expectEvent(t, ev, avscan.Upload, avscan.Unscanned, avscan.ReasonTimeout, avscan.Block)
	if calls := g.scanner.scanCalls(); len(calls) != 1 || !errors.Is(calls[0].ctxErr, context.Canceled) {
		t.Fatalf("scan calls %+v", calls)
	}
	if o.rec.connections() != 0 {
		t.Fatal("origin dialled after the client left")
	}
}
