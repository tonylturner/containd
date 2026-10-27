// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestAVObjectUnavailable(t *testing.T) {
	obj := scanObject([]byte("content"))
	if r := (*AVManager)(nil).Scan(context.Background(), obj); r.Reason != avscan.ReasonNotReady {
		t.Fatalf("nil manager = %+v", r)
	}
	m := newTestAVManager(t, AVOptions{})
	if r := m.Scan(context.Background(), obj); r.Reason != avscan.ReasonNotReady {
		t.Fatalf("disabled manager = %+v", r)
	}
	for _, cfg := range []config.AVConfig{
		{Enabled: true, Mode: "unknown"},
		{Enabled: true, Mode: "clamav", ClamAV: config.ClamAVConfig{SocketPath: filepath.Join(t.TempDir(), "missing.sock")}},
	} {
		m.lastCfg = cfg
		if r := m.Scan(context.Background(), obj); r.Verdict != avscan.Unscanned || r.Reason != avscan.ReasonScannerError {
			t.Fatalf("unavailable backend = %+v", r)
		}
	}
	if len(m.cache) != 0 {
		t.Fatal("unavailable backend cached a result")
	}
	if status := m.Status(context.Background()); status["errors_count"] == 0 {
		t.Fatalf("scan errors not counted: %+v", status)
	}
}

func TestAVObjectVerdictsAndUnscannedCache(t *testing.T) {
	for _, tc := range []struct {
		reply   string
		verdict avscan.Verdict
		reason  avscan.Reason
	}{
		{"stream: OK", avscan.Clean, ""},
		{"stream: Test.Signature FOUND", avscan.Infected, ""},
		{"INSTREAM size limit exceeded. ERROR", avscan.Unscanned, avscan.ReasonOversized},
		{"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND", avscan.Unscanned, avscan.ReasonOversized},
		{"stream: database unavailable ERROR", avscan.Unscanned, avscan.ReasonScannerError},
		{"stream: MAYBE", avscan.Unscanned, avscan.ReasonScannerError},
		{"", avscan.Unscanned, avscan.ReasonScannerError},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			var calls atomic.Int32
			socket := startFakeClamd(t, func(string, []byte) []byte {
				calls.Add(1)
				if tc.reply == "" {
					return nil
				}
				return []byte(tc.reply + "\x00")
			})
			m := newTestAVManager(t, AVOptions{})
			m.lastCfg = config.AVConfig{Enabled: true, Mode: "clamav", ClamAV: config.ClamAVConfig{SocketPath: socket}}
			for range 2 {
				r := m.Scan(context.Background(), scanObject([]byte("content")))
				if r.Verdict != tc.verdict || r.Reason != tc.reason || r.Backend != "clamav" {
					t.Fatalf("Scan = %+v", r)
				}
				if r.Verdict == avscan.Infected && r.Signature != "Test.Signature" {
					t.Fatalf("cached signature lost: %+v", r)
				}
			}
			wantCalls := int32(1)
			if tc.verdict == avscan.Unscanned {
				wantCalls = 2
			}
			if calls.Load() != wantCalls {
				t.Fatalf("backend calls = %d, want %d", calls.Load(), wantCalls)
			}
		})
	}
}

func TestAVObjectCacheEligibilityAndLimits(t *testing.T) {
	var calls atomic.Int32
	socket := startFakeClamd(t, func(string, []byte) []byte {
		calls.Add(1)
		return []byte("stream: OK\x00")
	})
	m := newTestAVManager(t, AVOptions{})
	m.lastCfg = config.AVConfig{Enabled: true, Mode: "clamav", MaxSizeBytes: 100, ClamAV: config.ClamAVConfig{SocketPath: socket}}
	obj := scanObject([]byte("12345"))
	for _, limit := range []int64{100, 100, 200, 4} {
		m.lastCfg.MaxSizeBytes = limit
		r := m.Scan(context.Background(), obj)
		if limit == 4 {
			if r.Reason != avscan.ReasonOversized {
				t.Fatalf("ineligible cached object = %+v", r)
			}
		} else if r.Verdict != avscan.Clean {
			t.Fatalf("Scan = %+v", r)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("size limit not in cache key: %d calls", calls.Load())
	}
	m.maxCache = 1
	m.cache = make(map[string]cachedVerdict)
	m.recordVerdict("expired", -time.Second, avscan.Result{Verdict: avscan.Clean})
	if _, ok := m.cachedVerdict("expired"); ok {
		t.Fatal("expired result retained")
	}
	m.recordVerdict("one", time.Minute, avscan.Result{Verdict: avscan.Clean})
	m.recordVerdict("two", time.Minute, avscan.Result{Verdict: avscan.Clean})
	if _, ok := m.cachedVerdict("one"); ok {
		t.Fatal("cache bound exceeded")
	}
}

func TestAVObjectConcurrencyBusyAndCancellation(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	socket := startFakeClamd(t, func(string, []byte) []byte {
		entered <- struct{}{}
		<-release
		return []byte("stream: OK\x00")
	})
	m := newTestAVManager(t, AVOptions{})
	m.slots = make(chan struct{}, 1)
	m.lastCfg = config.AVConfig{Enabled: true, Mode: "clamav", ClamAV: config.ClamAVConfig{SocketPath: socket}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan avscan.Result, 1)
	go func() { done <- m.Scan(ctx, scanObject([]byte("content"))) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("backend was not entered")
	}
	waitCtx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if r := m.Scan(waitCtx, scanObject([]byte("other"))); r.Reason != avscan.ReasonBusy {
		t.Fatalf("excess scan = %+v", r)
	}
	cancel()
	select {
	case r := <-done:
		if r.Verdict != avscan.Unscanned {
			t.Fatalf("cancelled scan = %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt socket read")
	}
}

func TestAVObjectShortBodyAndMidstreamClose(t *testing.T) {
	socket := startFakeClamd(t, nulReply("stream: OK"))
	m := newTestAVManager(t, AVOptions{})
	m.lastCfg = config.AVConfig{Enabled: true, Mode: "clamav", ClamAV: config.ClamAVConfig{SocketPath: socket}}
	obj := scanObject([]byte("short"))
	obj.Size++
	if r := m.Scan(context.Background(), obj); r.Reason != avscan.ReasonScannerError {
		t.Fatalf("short source = %+v", r)
	}

	path := filepath.Join(liveAVDir(t), "close.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = bufio.NewReader(c).ReadString(0)
	}()
	m.lastCfg.ClamAV.SocketPath = path
	if r := m.Scan(context.Background(), scanObject([]byte(strings.Repeat("x", 2*clamdChunkSize)))); r.Reason != avscan.ReasonScannerError {
		t.Fatalf("midstream close = %+v", r)
	}
	<-done
}

type shortAVWriter struct{}

func (shortAVWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestClamdShortWritesFail(t *testing.T) {
	if err := writeInstream(shortAVWriter{}, strings.NewReader("abc"), 3); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short writer = %v", err)
	}
}

func TestAVObjectTimeoutIsNotCached(t *testing.T) {
	var calls atomic.Int32
	socket := startFakeClamd(t, func(string, []byte) []byte {
		calls.Add(1)
		time.Sleep(100 * time.Millisecond)
		return []byte("stream: OK\x00")
	})
	m := newTestAVManager(t, AVOptions{})
	m.lastCfg = config.AVConfig{Enabled: true, Mode: "clamav", ClamAV: config.ClamAVConfig{SocketPath: socket}}
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		r := m.Scan(ctx, scanObject([]byte("content")))
		cancel()
		if r.Verdict != avscan.Unscanned || r.Reason != avscan.ReasonTimeout {
			t.Fatalf("slow reply = %+v", r)
		}
	}
	if calls.Load() != 2 || len(m.cache) != 0 {
		t.Fatalf("timeout was cached: %d calls, %d entries", calls.Load(), len(m.cache))
	}
}

func TestAVEmptyModeIsClamAV(t *testing.T) {
	socket := startFakeClamd(t, nulReply("stream: OK"))
	m := newTestAVManager(t, AVOptions{})
	m.lastCfg = config.AVConfig{Enabled: true, Mode: " ", ClamAV: config.ClamAVConfig{SocketPath: socket}}
	if r := m.Scan(context.Background(), scanObject([]byte("content"))); r.Verdict != avscan.Clean || r.Backend != "clamav" {
		t.Fatalf("empty mode = %+v", r)
	}
	if status := m.Status(context.Background()); status["mode"] != "clamav" {
		t.Fatalf("status mode = %v", status["mode"])
	}
}

func TestAVObjectICAPErrorsAreUnscanned(t *testing.T) {
	var calls atomic.Int32
	addr, _ := startFakeICAP(t, nil, func(req icapRequest) string {
		calls.Add(1)
		if string(req.Body) == "slow" {
			time.Sleep(time.Second)
		}
		return "ICAP/1.0 500 Server Error\r\n\r\n"
	})
	m := newTestAVManager(t, AVOptions{})
	m.lastCfg = config.AVConfig{Enabled: true, Mode: "icap", ICAP: config.ICAPConfig{Servers: []config.ICAPServer{{Address: addr}}}}
	for range 2 {
		r := m.Scan(context.Background(), scanObject([]byte("content")))
		if r.Verdict != avscan.Unscanned || r.Reason != avscan.ReasonScannerError || r.Backend != "icap|"+addr+"||false" {
			t.Fatalf("server error = %+v", r)
		}
	}
	if calls.Load() != 2 || len(m.cache) != 0 {
		t.Fatalf("scanner error was cached: %d calls, %d entries", calls.Load(), len(m.cache))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if r := m.Scan(ctx, scanObject([]byte("slow"))); r.Verdict != avscan.Unscanned || r.Reason != avscan.ReasonTimeout {
		t.Fatalf("slow reply = %+v", r)
	}
	if time.Since(start) > 800*time.Millisecond {
		t.Fatalf("caller deadline not honoured: %s", time.Since(start))
	}
	if status := m.Status(context.Background()); status["errors_count"] != 3 {
		t.Fatalf("scan errors = %+v", status)
	}
}

func TestAVObjectICAPVerdictsAreNotCached(t *testing.T) {
	for _, verdict := range []avscan.Verdict{avscan.Clean, avscan.Infected} {
		t.Run(string(verdict), func(t *testing.T) {
			var calls atomic.Int32
			addr, _ := startFakeICAP(t, nil, func(icapRequest) string {
				calls.Add(1)
				if verdict == avscan.Infected {
					return "ICAP/1.0 204 No Content\r\nX-Infection-Found: Type=0; Resolution=2; Threat=Test;\r\n\r\n"
				}
				return "ICAP/1.0 204 No Content\r\n\r\n"
			})
			m := newTestAVManager(t, AVOptions{})
			m.lastCfg = config.AVConfig{Enabled: true, Mode: "icap", ICAP: config.ICAPConfig{Servers: []config.ICAPServer{icapServer(addr)}}}
			payload := []byte("same content")
			// Even identical contexts must reach ICAP again, as must a
			// change of direction with the same digest.
			for i, obj := range []avscan.Object{scanObject(payload), scanObject(payload), uploadObject(payload)} {
				r := m.Scan(context.Background(), obj)
				if r.Verdict != verdict {
					t.Fatalf("scan %d = %+v, want %s", i, r, verdict)
				}
				if verdict == avscan.Infected && r.Signature != "Test" {
					t.Fatalf("scan %d lost signature: %+v", i, r)
				}
				if calls.Load() != int32(i+1) || len(m.cache) != 0 {
					t.Fatalf("scan %d: %d backend calls, %d cached verdicts", i, calls.Load(), len(m.cache))
				}
			}
		})
	}
}

func TestAVReloadProbeAloneIsNotReady(t *testing.T) {
	fake := newFakeClamAV(t)
	fake.opts.DatabaseDir = t.TempDir()
	m := newTestAVManager(t, fake.opts)
	cfg := clamavConfig(fake.socket())
	cfg.ClamAV.FreshclamEnabled = false
	cfg.ClamAV.CustomDefsPath = t.TempDir()
	if err := os.WriteFile(filepath.Join(m.opts.DatabaseDir, reloadProbeFile), []byte("Probe:0:*:4142434445\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(applyCtx(t), cfg); err == nil || !strings.Contains(err.Error(), "signature database is required") {
		t.Fatalf("probe-only database accepted: %v", err)
	}
	if ready, why := m.Ready(); ready || !strings.Contains(why, "signature database is required") {
		t.Fatalf("probe-only readiness = %v, %s", ready, why)
	}
	m.mu.Lock()
	gen, running := m.defsGen, m.clamd.running()
	m.mu.Unlock()
	if gen != 0 || running {
		t.Fatalf("probe-only backend activated: generation %d running %v", gen, running)
	}
}

func TestAVReloadCompletionFence(t *testing.T) {
	fake := newFakeClamAV(t)
	gate := filepath.Join(t.TempDir(), "allow-reload")
	t.Setenv("CONTAIND_TEST_RELOAD_GATE", gate)
	m := newTestAVManager(t, fake.opts)
	m.validateDef = func(context.Context, string) error { return nil }
	cfg := clamavConfig(fake.socket())
	cfg.ClamAV.FreshclamEnabled = false
	cfg.ClamAV.CustomDefsPath = t.TempDir()
	if err := m.Apply(applyCtx(t), cfg); err != nil {
		t.Fatal(err)
	}
	generation := func() uint64 {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.defsGen
	}
	old := generation()
	obj := scanObject([]byte("ordinary object"))
	if r := m.Scan(context.Background(), obj); r.Verdict != avscan.Clean {
		t.Fatal(r)
	}
	done := make(chan error, 1)
	go func() {
		_, err := m.UploadDefinition(context.Background(), "test.ndb", strings.NewReader("Test:0:*:4142434445"))
		done <- err
	}()
	waitFor(t, 3*time.Second, func() bool { return countLines(fake.clamdLog, "RELOAD") == 1 })
	if generation() != old {
		t.Fatal("RELOADING prematurely advanced generation")
	}
	if ready, why := m.Ready(); !ready {
		t.Fatalf("usable old database is not ready during reload: %s", why)
	}
	if r := m.Scan(context.Background(), obj); r.Verdict != avscan.Clean {
		t.Fatal(r)
	}
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if generation() != old+1 {
		t.Fatal("confirmed probe did not advance generation")
	}
	before := countLines(fake.clamdLog, "INSTREAM")
	if r := m.Scan(context.Background(), obj); r.Verdict != avscan.Clean {
		t.Fatal(r)
	}
	if countLines(fake.clamdLog, "INSTREAM") != before+1 {
		t.Fatal("confirmed generation reused old cache")
	}
	// Changing only the custom database directory also requires proof.
	cfg.ClamAV.CustomDefsPath = t.TempDir()
	if err := m.Apply(applyCtx(t), cfg); err != nil {
		t.Fatal(err)
	}
	if generation() != old+2 || countLines(fake.clamdLog, "RELOAD") != 2 {
		t.Fatal("customDefsPath change did not reload and advance generation")
	}
	if err := m.DeleteDefinition(context.Background(), "missing.ndb"); !errors.Is(err, ErrAVInvalid) {
		t.Fatalf("missing definition = %v", err)
	}

	// A caller's deadline does not decide an activation. With the proof
	// withheld, a short Apply returns with the activation pending, the old
	// database keeps serving under the old generation, and the backend turns
	// not ready only when the confirmation window expires.
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.bounds = reloadBounds{confirm: 2 * time.Second, retryMin: 50 * time.Millisecond, retryMax: 200 * time.Millisecond}
	m.mu.Unlock()
	cfg.ClamAV.CustomDefsPath = t.TempDir()
	short, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := m.Apply(short, cfg); err != nil {
		t.Fatalf("Apply with the activation pending = %v", err)
	}
	if generation() != old+2 {
		t.Fatal("unconfirmed reload advanced generation")
	}
	if ready, why := m.Ready(); !ready {
		t.Fatalf("usable old database is not ready while the activation is pending: %s", why)
	}
	if m.Status(context.Background())["reload_pending"] != true {
		t.Fatal("pending activation not reported")
	}
	if r := m.Scan(context.Background(), obj); r.Verdict != avscan.Clean {
		t.Fatal(r)
	}
	waitFor(t, 4*time.Second, func() bool { ready, _ := m.Ready(); return !ready })
	if ready, why := m.Ready(); ready || !strings.Contains(why, "completion unconfirmed") {
		t.Fatalf("expired confirmation readiness = %v, %s", ready, why)
	}
	if generation() != old+2 {
		t.Fatal("failed proof advanced generation")
	}
	if r := m.Scan(context.Background(), obj); r.Reason != avscan.ReasonNotReady {
		t.Fatalf("failed reload served old cache: %+v", r)
	}

	// The retry re-issues the reload and clears the failure once clamd
	// proves the activation.
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return generation() == old+3 })
	if ready, why := m.Ready(); !ready {
		t.Fatalf("confirmed retry not ready: %s", why)
	}
	status := m.Status(context.Background())
	if status["reload_pending"] != false || status["ready_error"] != "" {
		t.Fatalf("status after confirmed retry = %+v", status)
	}
	if countLines(fake.clamdLog, "RELOAD") < 4 {
		t.Fatalf("retry did not re-issue RELOAD: %v", readLines(fake.clamdLog))
	}
}

func TestAVScanCallerDeadlineGovernsScan(t *testing.T) {
	// Scanning a large object outlasts timeoutSec, which bounds only the
	// connection when the caller sets a deadline.
	var streamed atomic.Int64
	socket := startFakeClamd(t, func(_ string, stream []byte) []byte {
		streamed.Store(int64(len(stream)))
		time.Sleep(1500 * time.Millisecond)
		return []byte("stream: OK\x00")
	})
	m := newTestAVManager(t, AVOptions{})
	m.lastCfg = config.AVConfig{Enabled: true, Mode: "clamav", TimeoutSec: 1, ClamAV: config.ClamAVConfig{SocketPath: socket}}
	large := bytes.Repeat([]byte("clean"), 3*clamdChunkSize/5+1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if r := m.Scan(ctx, scanObject(large)); r.Verdict != avscan.Clean {
		t.Fatalf("large object under the caller's deadline = %+v", r)
	}
	if streamed.Load() != int64(len(large)) {
		t.Fatalf("clamd received %d of %d bytes", streamed.Load(), len(large))
	}
	// Without a caller deadline, timeoutSec bounds the scan instead.
	other := bytes.Repeat([]byte("other"), 3*clamdChunkSize/5+1)
	if r := m.Scan(context.Background(), scanObject(other)); r.Reason != avscan.ReasonTimeout {
		t.Fatalf("scan without a deadline = %+v", r)
	}
}
