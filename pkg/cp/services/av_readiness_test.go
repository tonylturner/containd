// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
)

const (
	icapReadyReply = "ICAP/1.0 200 OK\r\nMethods: REQMOD, RESPMOD\r\nEncapsulated: null-body=0\r\n\r\n"
	icapCleanReply = "ICAP/1.0 204 No Content\r\n\r\n"
	icapErrorReply = "ICAP/1.0 500 Server Error\r\n\r\n"
	// Include one in-flight probe and scheduling tolerance on loaded runners.
	readinessTestBound = avObserveInterval + 2*avStatusProbeTimeout + time.Second
)

// readinessICAP can be stopped and rebound at the same address. Shutdown
// joins every accepted connection, including a deliberately stalled probe.
type readinessICAP struct {
	ln       net.Listener
	mu       sync.Mutex
	conns    map[net.Conn]bool
	wg       sync.WaitGroup
	once     sync.Once
	accepted chan struct{}
}

func startReadinessICAP(t *testing.T, addr string, reply func(icapRequest) string) *readinessICAP {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &readinessICAP{ln: ln, conns: make(map[net.Conn]bool), accepted: make(chan struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(s.accepted)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns[conn] = true
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				defer func() {
					s.mu.Lock()
					delete(s.conns, conn)
					s.mu.Unlock()
				}()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				req, err := readStrictICAPRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				// The callback sees only complete requests, never a
				// request whose body cancellation can still truncate.
				out := reply(req)
				if out == "" {
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				_, _ = io.WriteString(conn, out)
			}()
		}
	}()
	t.Cleanup(s.stop)
	return s
}

func (s *readinessICAP) stop() {
	s.once.Do(func() {
		_ = s.ln.Close()
		<-s.accepted
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}

func readinessICAPConfig(s *readinessICAP) config.AVConfig {
	return config.AVConfig{
		Enabled: true, Mode: "icap", HTTPDownload: true, HTTPUpload: true,
		ICAP: config.ICAPConfig{Servers: []config.ICAPServer{{Address: s.ln.Addr().String()}}},
	}
}

func assertAVReady(t *testing.T, m *AVManager, want bool) {
	t.Helper()
	if ready, why := m.Ready(); ready != want {
		t.Fatalf("Ready = %v (%s), want %v", ready, why, want)
	}
}

func waitAVReady(t *testing.T, m *AVManager, want bool) {
	t.Helper()
	waitFor(t, readinessTestBound, func() bool { ready, _ := m.Ready(); return ready == want })
}

func TestAVReadinessICAPLossAndRecovery(t *testing.T) {
	s := startReadinessICAP(t, "127.0.0.1:0", func(icapRequest) string { return icapReadyReply })
	m := newTestAVManager(t, AVOptions{})
	if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
		t.Fatal(err)
	}
	assertAVReady(t, m, true)
	addr := s.ln.Addr().String()
	s.stop()
	// No scans, Status calls or reapply drive either transition.
	waitAVReady(t, m, false)
	startReadinessICAP(t, addr, func(icapRequest) string { return icapReadyReply })
	waitAVReady(t, m, true)
}

func TestAVReadinessClamdLossAndRecovery(t *testing.T) {
	fake := newFakeClamAV(t)
	m := newTestAVManager(t, fake.opts)
	cfg := clamavConfig(fake.socket())
	cfg.ClamAV.FreshclamEnabled = false
	cfg.ClamAV.CustomDefsPath = t.TempDir()
	if err := m.Apply(applyCtx(t), cfg); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	process := m.clamd.cmd.Process
	exited := m.clamd.done
	m.mu.Unlock()
	// Suspend the real fake child, keeping the socket and process alive:
	// only the bounded PING probe (not the process-exit check) detects loss.
	t.Cleanup(func() { _ = process.Signal(syscall.SIGCONT) })
	if err := process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	waitAVReady(t, m, false)
	m.mu.Lock()
	running := m.clamd.running()
	m.mu.Unlock()
	if !running {
		t.Fatal("test must exercise probe failure, not child exit")
	}
	if err := process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	waitAVReady(t, m, true)
	// Also stop and restart the backend process itself, without another
	// Apply or Status call. The manager still owns/reaps both child runs.
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(readinessTestBound):
		t.Fatal("clamd did not exit")
	}
	waitFor(t, readinessTestBound, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return !m.backendReady
	})
	assertAVReady(t, m, false)
	if err := m.ensureClamd(cfg); err != nil {
		t.Fatal(err)
	}
	waitAVReady(t, m, true)
}

func TestAVReadinessClamdScanResultClassification(t *testing.T) {
	for _, tc := range []struct {
		reply string
		ready bool
	}{
		{"stream: OK\x00", true},
		{"stream: Test FOUND\x00", true},
		{"stream: INSTREAM size limit exceeded. ERROR\x00", true},
		{"stream: object processing failed ERROR\x00", true},
		{"stream: MAYBE\x00", false},
		{"malformed ERROR\x00", false},
		{"", false},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			socket := startFakeClamd(t, func(string, []byte) []byte { return []byte(tc.reply) })
			m := newTestAVManager(t, AVOptions{})
			m.lastCfg = clamavConfig(socket)
			m.backendReady = true
			m.Scan(context.Background(), scanObject([]byte("object")))
			m.mu.Lock()
			ready := m.backendReady
			m.mu.Unlock()
			if ready != tc.ready {
				t.Fatalf("backend availability = %v, want %v", ready, tc.ready)
			}
		})
	}
}

func TestAVReadinessScanAndStatusPublish(t *testing.T) {
	var failed atomic.Bool
	var objectReply atomic.Value
	objectReply.Store(icapCleanReply)
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
		if failed.Load() {
			return icapErrorReply
		}
		if req.Method == "OPTIONS" {
			return icapReadyReply
		}
		return objectReply.Load().(string)
	})
	m := newTestAVManager(t, AVOptions{})
	if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
		t.Fatal(err)
	}
	failed.Store(true)
	if res := m.Scan(context.Background(), scanObject([]byte("object"))); res.Verdict != avscan.Unscanned {
		t.Fatal(res)
	}
	assertAVReady(t, m, false)
	// A local body/head error must not falsely restore a failed backend.
	bad := scanObject([]byte("object"))
	bad.ResponseHead = nil
	m.Scan(context.Background(), bad)
	assertAVReady(t, m, false)
	failed.Store(false)
	if res := m.Scan(context.Background(), scanObject([]byte("object"))); res.Verdict != avscan.Clean {
		t.Fatal(res)
	}
	assertAVReady(t, m, true)
	objectReply.Store("ICAP/1.0 413 Request Entity Too Large\r\n\r\n")
	if res := m.Scan(context.Background(), scanObject([]byte("object"))); res.Reason != avscan.ReasonOversized {
		t.Fatal(res)
	}
	assertAVReady(t, m, true)
	objectReply.Store("ICAP/1.0 200 OK\r\nX-Virus-ID: Test\r\n\r\n")
	if res := m.Scan(context.Background(), scanObject([]byte("object"))); res.Verdict != avscan.Infected {
		t.Fatal(res)
	}
	assertAVReady(t, m, true)
	bad = scanObject([]byte("short"))
	bad.Size++
	m.Scan(context.Background(), bad)
	assertAVReady(t, m, true)
	bad.ResponseHead = nil
	m.Scan(context.Background(), bad)
	assertAVReady(t, m, true)
	failed.Store(true)
	if status := m.Status(context.Background()); status["ready"] != false {
		t.Fatal(status)
	}
	assertAVReady(t, m, false)
	failed.Store(false)
	if status := m.Status(context.Background()); status["ready"] != true {
		t.Fatal(status)
	}
	assertAVReady(t, m, true)
}

func TestAVReadinessFailedApplyRecoversAndDisableJoins(t *testing.T) {
	var failed atomic.Bool
	failed.Store(true)
	s := startReadinessICAP(t, "127.0.0.1:0", func(icapRequest) string {
		if failed.Load() {
			return icapErrorReply
		}
		return icapReadyReply
	})
	m := newTestAVManager(t, AVOptions{})
	if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err == nil {
		t.Fatal("unavailable backend apply succeeded")
	}
	assertAVReady(t, m, false)
	failed.Store(false)
	waitAVReady(t, m, true)
	done := m.observeDone
	if err := m.Apply(applyCtx(t), config.AVConfig{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	default:
		t.Fatal("disable did not join observer")
	}
	if m.observeDone != nil {
		t.Fatal("disabled backend started an observer")
	}
	assertAVReady(t, m, false)
}

func TestAVReadinessObserverReplacementAndStopJoin(t *testing.T) {
	var stall atomic.Bool
	entered := make(chan struct{}, 4)
	s := startReadinessICAP(t, "127.0.0.1:0", func(icapRequest) string {
		if stall.Load() {
			entered <- struct{}{}
			return ""
		}
		return icapReadyReply
	})
	healthy := startReadinessICAP(t, "127.0.0.1:0", func(icapRequest) string { return icapReadyReply })
	m := newTestAVManager(t, AVOptions{})
	for i := range 2 {
		stall.Store(false)
		if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
			t.Fatal(err)
		}
		done := m.observeDone
		stall.Store(true)
		select {
		case <-entered:
		case <-time.After(readinessTestBound):
			t.Fatal("observer never probed")
		}
		// Ready must remain lock-only even while the backend is hung.
		start := time.Now()
		for range 100 {
			m.Ready()
		}
		if time.Since(start) > 100*time.Millisecond {
			t.Fatal("Ready blocked on network I/O")
		}
		if i == 0 {
			if err := m.Apply(applyCtx(t), readinessICAPConfig(healthy)); err != nil {
				t.Fatal(err)
			}
			assertAVReady(t, m, true)
		} else if err := m.Stop(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		default:
			t.Fatal("retired observer was not joined")
		}
	}
	assertAVReady(t, m, false)
}

func TestAVReadinessSupersededResults(t *testing.T) {
	for _, operation := range []string{"scan", "status"} {
		t.Run(operation, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var block atomic.Bool
			var once sync.Once
			s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
				if block.Load() {
					once.Do(func() { close(entered) })
					<-release
					return icapErrorReply
				}
				return icapReadyReply
			})
			m := newTestAVManager(t, AVOptions{})
			if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
				t.Fatal(err)
			}
			// Remove observer timing from this stale-result test. Its
			// cancellation/join behavior is covered separately above.
			m.stopObserver()
			block.Store(true)
			done := make(chan struct{})
			go func() {
				defer close(done)
				if operation == "scan" {
					m.Scan(context.Background(), scanObject([]byte("object")))
				} else {
					m.Status(context.Background())
				}
			}()
			select {
			case <-entered:
			case <-time.After(readinessTestBound):
				close(release)
				t.Fatal("request never arrived")
			}
			healthy := startReadinessICAP(t, "127.0.0.1:0", func(icapRequest) string { return icapReadyReply })
			if err := m.Apply(applyCtx(t), readinessICAPConfig(healthy)); err != nil {
				close(release)
				t.Fatal(err)
			}
			close(release)
			<-done
			assertAVReady(t, m, true)
		})
	}
}
