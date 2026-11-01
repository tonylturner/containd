// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// A completion in the still-supported direction must not erase OPTIONS
// method loss, even if the scan started before that capability observation.
func TestAVReadinessInFlightScanCannotEraseMethodLoss(t *testing.T) {
	for _, dir := range []avscan.Direction{avscan.Upload, avscan.Download} {
		t.Run(string(dir), func(t *testing.T) {
			var partial atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
				if req.Method == "OPTIONS" && partial.Load() {
					method := icapRESPMOD
					if dir == avscan.Upload {
						method = icapREQMOD
					}
					return "ICAP/1.0 200 OK\r\nMethods: " + method + "\r\n\r\n"
				}
				if req.Method != "OPTIONS" && !bytes.Equal(req.Body, []byte(avCanaryPayload)) {
					close(entered)
					<-release
				}
				return healthyReadinessReply(req)
			})
			m := newTestAVManager(t, AVOptions{})
			if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
				t.Fatal(err)
			}
			m.stopObserver()
			obj := scanObject([]byte("object"))
			if dir == avscan.Upload {
				obj = uploadObject([]byte("object"))
			}
			done := make(chan avscan.Result, 1)
			go func() { done <- m.Scan(context.Background(), obj) }()
			select {
			case <-entered:
			case <-time.After(readinessTestBound):
				t.Fatal("scan never arrived")
			}
			partial.Store(true)
			if status := m.Status(context.Background()); status["ready"] != false {
				t.Fatal(status)
			}
			unblock()
			if res := <-done; res.Verdict != avscan.Clean {
				t.Fatal(res)
			}
			assertAVReady(t, m, false)
		})
	}
}

func TestAVReadinessPartialMethodsCannotRecoverByOneScan(t *testing.T) {
	for _, dir := range []avscan.Direction{avscan.Upload, avscan.Download} {
		t.Run(string(dir), func(t *testing.T) {
			s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
				if req.Method == "OPTIONS" {
					method := icapRESPMOD
					if dir == avscan.Upload {
						method = icapREQMOD
					}
					return "ICAP/1.0 200 OK\r\nMethods: " + method + "\r\n\r\n"
				}
				return healthyReadinessReply(req)
			})
			m := newTestAVManager(t, AVOptions{})
			if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err == nil {
				t.Fatal("missing method accepted")
			}
			obj := scanObject([]byte("object"))
			if dir == avscan.Upload {
				obj = uploadObject([]byte("object"))
			}
			if res := m.Scan(context.Background(), obj); res.Verdict != avscan.Clean {
				t.Fatal(res)
			}
			assertAVReady(t, m, false)
		})
	}
}

func TestAVReadinessOptionsCannotProveScanning(t *testing.T) {
	var broken atomic.Bool
	var bypass atomic.Bool
	var canaries atomic.Int32
	var options atomic.Int32
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
		failed, passThrough := broken.Load(), bypass.Load()
		if req.Method == "OPTIONS" {
			options.Add(1)
			return icapReadyReply
		}
		if bytes.Equal(req.Body, []byte(avCanaryPayload)) {
			canaries.Add(1)
		}
		if failed {
			return icapErrorReply
		}
		if passThrough {
			return icapCleanReply
		}
		return healthyReadinessReply(req)
	})
	m := newTestAVManager(t, AVOptions{})
	var events atomic.Int32
	m.OnEvent = func(string, map[string]any) { events.Add(1) }
	if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
		t.Fatal(err)
	}
	if canaries.Load() != 2 {
		t.Fatalf("initial canaries = %d", canaries.Load())
	}
	eventsBefore := events.Load()
	broken.Store(true)
	if res := m.Scan(context.Background(), scanObject([]byte("object"))); res.Verdict != avscan.Unscanned {
		t.Fatal(res)
	}
	assertAVReady(t, m, false)
	probes := options.Load()
	waitFor(t, readinessTestBound, func() bool { return options.Load() > probes && canaries.Load() > 2 })
	assertAVReady(t, m, false)
	// OPTIONS and even clean object replies do not prove antivirus is enabled.
	broken.Store(false)
	bypass.Store(true)
	attempts := canaries.Load()
	waitFor(t, readinessTestBound, func() bool { return canaries.Load() > attempts })
	assertAVReady(t, m, false)
	if res := m.Scan(context.Background(), scanObject([]byte("clean"))); res.Verdict != avscan.Clean {
		t.Fatal(res)
	}
	assertAVReady(t, m, false)
	bypass.Store(false)
	waitAVReady(t, m, true)
	if events.Load() != eventsBefore {
		t.Fatal("canary emitted an event")
	}
	status := m.Status(context.Background())
	if status["detections"] != 0 || status["count"] != 2 {
		t.Fatalf("canaries entered counters: %v", status)
	}
	attempts = canaries.Load()
	probes = options.Load()
	waitFor(t, readinessTestBound, func() bool { return options.Load() > probes })
	if canaries.Load() != attempts {
		t.Fatal("healthy directions scanned a canary")
	}
}

func TestAVReadinessInitialCanaryRejectsBypass(t *testing.T) {
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
		if req.Method == "OPTIONS" {
			return icapReadyReply
		}
		return icapCleanReply
	})
	m := newTestAVManager(t, AVOptions{})
	if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err == nil || !strings.Contains(err.Error(), "EICAR must be reported infected") {
		t.Fatalf("Apply = %v", err)
	}
	assertAVReady(t, m, false)
}

func TestAVReadinessCanceledStatusDoesNotPublish(t *testing.T) {
	for _, phase := range []string{"before", "during", "deadline"} {
		t.Run(phase, func(t *testing.T) {
			var stall atomic.Bool
			entered := make(chan struct{}, 1)
			s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
				if stall.Load() {
					entered <- struct{}{}
					return ""
				}
				return healthyReadinessReply(req)
			})
			m := newTestAVManager(t, AVOptions{})
			if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
				t.Fatal(err)
			}
			m.stopObserver()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "before" {
				cancel()
			} else {
				stall.Store(true)
			}
			if phase == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
			}
			done := make(chan map[string]any, 1)
			go func() { done <- m.Status(ctx) }()
			if phase != "before" {
				select {
				case <-entered:
				case <-time.After(readinessTestBound):
					t.Fatal("status never arrived")
				}
				if phase == "during" {
					cancel()
				}
			}
			status := <-done
			if status["ready"] != false || status["ready_error"] == "" {
				t.Fatalf("missing diagnostic: %v", status)
			}
			assertAVReady(t, m, true)
		})
	}
}

func TestAVReadinessUnchangedReapplyKeepsProof(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var slow atomic.Bool
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
		if slow.Load() && req.Method == "OPTIONS" {
			close(entered)
			<-release
		}
		return healthyReadinessReply(req)
	})
	m := newTestAVManager(t, AVOptions{})
	cfg := readinessICAPConfig(s)
	if err := m.Apply(applyCtx(t), cfg); err != nil {
		t.Fatal(err)
	}
	m.stopObserver()
	slow.Store(true)
	done := make(chan error, 1)
	go func() { done <- m.Apply(context.Background(), cfg) }()
	select {
	case <-entered:
	case <-time.After(readinessTestBound):
		t.Fatal("reapply never arrived")
	}
	for range 10 {
		assertAVReady(t, m, true)
		time.Sleep(10 * time.Millisecond)
	}
	slow.Store(false)
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertAVReady(t, m, true)
}

func TestAVReadinessSameEpochStartOrdering(t *testing.T) {
	for _, staleHealthy := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale failure", true: "stale success"}[staleHealthy], func(t *testing.T) {
			m := newTestAVManager(t, AVOptions{})
			m.lastCfg.Enabled = true
			m.lastCfg.Mode = "icap"
			m.lastCfg.HTTPDownload = true
			m.configureDirectionsLocked(m.lastCfg)
			m.directions[avscan.Download] = avDirectionHealth{capable: true, healthy: true}
			older := m.nextProbeLocked()
			newer := m.nextProbeLocked()
			m.publishScan(0, newer, avscan.Download, !staleHealthy, false, "newer failure")
			m.publishScan(0, older, avscan.Download, staleHealthy, false, "stale failure")
			assertAVReady(t, m, !staleHealthy)
		})
	}
}

func TestAVReadinessSameEpochLateStatus(t *testing.T) {
	for _, staleSuccess := range []bool{false, true} {
		t.Run(map[bool]string{false: "late failure", true: "late success"}[staleSuccess], func(t *testing.T) {
			var block, first atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
				if block.Load() && req.Method == "OPTIONS" {
					success := !staleSuccess
					if first.CompareAndSwap(true, false) {
						close(entered)
						<-release
						success = staleSuccess
					}
					if !success {
						return icapErrorReply
					}
				}
				return healthyReadinessReply(req)
			})
			m := newTestAVManager(t, AVOptions{})
			if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
				t.Fatal(err)
			}
			m.stopObserver()
			first.Store(true)
			block.Store(true)
			done := make(chan struct{})
			go func() { defer close(done); m.Status(context.Background()) }()
			select {
			case <-entered:
			case <-time.After(readinessTestBound):
				t.Fatal("status never arrived")
			}
			m.Status(context.Background())
			assertAVReady(t, m, !staleSuccess)
			unblock()
			<-done
			assertAVReady(t, m, !staleSuccess)
		})
	}
}

// Start ordering applies to each fact, not globally: otherwise a newer
// OPTIONS reply could hide a failed scan, or busy downloads could discard
// every observation that the upload capability has disappeared.
func TestAVReadinessIndependentFactOrdering(t *testing.T) {
	for _, delayed := range []string{"capability", "scan"} {
		t.Run(delayed, func(t *testing.T) {
			var block atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
				shouldBlock := delayed == "capability" && req.Method == "OPTIONS" || delayed == "scan" && req.Method != "OPTIONS"
				if block.Load() && shouldBlock {
					close(entered)
					<-release
					if delayed == "capability" {
						return "ICAP/1.0 200 OK\r\nMethods: RESPMOD\r\n\r\n"
					}
					return icapErrorReply
				}
				return healthyReadinessReply(req)
			})
			m := newTestAVManager(t, AVOptions{})
			if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
				t.Fatal(err)
			}
			m.stopObserver()
			block.Store(true)
			done := make(chan struct{})
			scan := func() { m.Scan(context.Background(), scanObject([]byte("object"))) }
			status := func() { m.Status(context.Background()) }
			older, newer := status, scan
			if delayed == "scan" {
				older, newer = scan, status
			}
			go func() { defer close(done); older() }()
			select {
			case <-entered:
			case <-time.After(readinessTestBound):
				t.Fatal("request never arrived")
			}
			newer()
			unblock()
			<-done
			assertAVReady(t, m, false)
		})
	}
}

func TestAVReadinessClamdCanaryProof(t *testing.T) {
	var scans atomic.Int32
	var bypass atomic.Bool
	socket := startFakeClamd(t, func(cmd string, body []byte) []byte {
		switch cmd {
		case "PING":
			return []byte("PONG\x00")
		case "VERSION":
			return []byte("ClamAV test/1\x00")
		case "INSTREAM":
			scans.Add(1)
			if bytes.Equal(body, []byte(avCanaryPayload)) && !bypass.Load() {
				return []byte("stream: Eicar-Test FOUND\x00")
			}
			return []byte("stream: OK\x00")
		}
		return nil
	})
	m := newTestAVManager(t, AVOptions{})
	cfg := clamavConfig(socket)
	cfg.HTTPUpload = true
	cfg.HTTPDownload = true
	m.lastCfg = cfg
	m.configureDirectionsLocked(cfg)
	bypass.Store(true)
	if ready, _, _ := m.observeBackend(context.Background(), cfg, 0, true, true); ready {
		t.Fatal("clean clamd canary accepted")
	}
	bypass.Store(false)
	if ready, _, why := m.observeBackend(context.Background(), cfg, 0, true, true); !ready {
		t.Fatal(why)
	}
	if scans.Load() != 4 {
		t.Fatalf("canaries = %d", scans.Load())
	}
	if m.detections != 0 {
		t.Fatal("canary recorded as detection")
	}
	if ready, _, why := m.observeBackend(context.Background(), cfg, 0, true, true); !ready {
		t.Fatal(why)
	}
	if scans.Load() != 4 {
		t.Fatal("healthy native paths canary-scanned")
	}
}
