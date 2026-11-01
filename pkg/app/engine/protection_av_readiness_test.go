// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http/httputil"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"go.uber.org/zap"
)

// A real ICAP transport that can stop and rebind. Complete request bodies are
// consumed before recording scans or replying, so shutdown cannot truncate a
// canary whose detection the test has already observed.
type protectionICAP struct {
	ln     net.Listener
	done   chan struct{}
	mu     sync.Mutex
	conn   net.Conn
	bypass atomic.Bool
	scans  atomic.Int32
}

func startProtectionICAP(t *testing.T, addr string, bypass bool) *protectionICAP {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &protectionICAP{ln: ln, done: make(chan struct{})}
	s.bypass.Store(bypass)
	go func() {
		defer close(s.done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conn = c
			s.mu.Unlock()
			s.serve(c)
			_ = c.Close()
			s.mu.Lock()
			s.conn = nil
			s.mu.Unlock()
		}
	}()
	t.Cleanup(s.stop)
	return s
}

func (s *protectionICAP) stop() {
	_ = s.ln.Close()
	s.mu.Lock()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.mu.Unlock()
	<-s.done
}

func (s *protectionICAP) serve(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return
	}
	h, err := tp.ReadMIMEHeader()
	if err != nil {
		return
	}
	if strings.HasPrefix(line, "OPTIONS ") {
		_, _ = io.WriteString(c, "ICAP/1.0 200 OK\r\nMethods: REQMOD, RESPMOD\r\nOptions-TTL: 1\r\nEncapsulated: null-body=0\r\n\r\n")
		return
	}
	// The final encapsulated section starts the chunked scan body.
	sections := strings.Split(h.Get("Encapsulated"), ",")
	_, offset, ok := strings.Cut(strings.TrimSpace(sections[len(sections)-1]), "=")
	n, err := strconv.ParseInt(offset, 10, 64)
	if !ok || err != nil || n < 0 {
		return
	}
	if _, err := io.CopyN(io.Discard, br, n); err != nil {
		return
	}
	body, err := io.ReadAll(httputil.NewChunkedReader(br))
	if err != nil {
		return
	}
	const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	s.scans.Add(1)
	reply := "ICAP/1.0 204 No Content\r\n\r\n"
	if string(body) == eicar && !s.bypass.Load() {
		reply = "ICAP/1.0 200 OK\r\nX-Virus-ID: Eicar-Test\r\n\r\n"
	}
	_, _ = io.WriteString(c, reply)
}

func TestProtectionICAPStoppedAfterSuccessfulApply(t *testing.T) {
	t.Setenv("CONTAIND_LOG_FILE", "off")
	server := startProtectionICAP(t, "127.0.0.1:0", false)
	av := services.NewAVManager(context.Background(), services.AVOptions{StateDir: t.TempDir(), DatabaseDir: t.TempDir()})
	t.Cleanup(func() {
		if err := av.Stop(); err != nil {
			t.Error(err)
		}
	})
	dp, err := engine.New(engine.Config{Enforce: engine.EnforceConfig{
		Enabled: true, Applier: adoptionApplier{},
		ClearMark: func(context.Context, uint32, uint32, uint32) (int, error) { return 0, nil },
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dp.Close)
	env := newGateTestEnv(t)
	env.g.scanner, env.g.protection = av, dp
	c := testProtectionCoordinator(t, dp)
	svc := config.ServicesConfig{AV: config.AVConfig{
		Enabled: true, Mode: "icap", HTTPUpload: true, HTTPDownload: true,
		ICAP: config.ICAPConfig{Servers: []config.ICAPServer{{Address: server.ln.Addr().String()}}},
	}}
	body, err := json.Marshal(svc)
	if err != nil {
		t.Fatal(err)
	}
	if w := coordinatedPost(servicesHandler(zap.NewNop().Sugar(), dp, nil, nil, av, env.g, c), "live-av", string(body)); w.Code != 200 {
		t.Fatalf("services: %d %s", w.Code, w.Body)
	}
	env.g.setEnforcing(true)
	body, err = json.Marshal(rules.Snapshot{Gate: rules.GateSelection{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if w := coordinatedPost(applyRulesHandler(dp, env.g, c), "live-av", string(body)); w.Code != 200 {
		t.Fatalf("apply: %d %s", w.Code, w.Body)
	}
	await := func(check func() bool) {
		t.Helper()
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("live readiness did not converge: %+v", dp.Protection())
	}
	state := func(want string) func() bool {
		return func() bool { return dp.Protection().State == want }
	}
	await(state("protecting"))
	if server.scans.Load() != 2 {
		t.Fatalf("initial upload/download canaries = %d, want 2", server.scans.Load())
	}
	addr := server.ln.Addr().String()
	server.stop()
	// No Status/health probe, scan, reapply or retry drives these transitions.
	await(state("pending"))
	recovered := startProtectionICAP(t, addr, true)
	await(func() bool { return recovered.scans.Load() >= 2 })
	if ready, why := av.Ready(); ready || dp.Protection().State != "pending" {
		t.Fatalf("OPTIONS plus bypassed canaries restored protection: ready=%v (%s), %+v", ready, why, dp.Protection())
	}
	recovered.bypass.Store(false)
	await(state("protecting"))
	st := dp.Protection()
	if st.ApplyID != "live-av" || st.InstalledApplyID != "live-av" || recovered.scans.Load() < 4 {
		t.Fatalf("recovery must prove both directions without a new apply: %+v, scans=%d", st, recovered.scans.Load())
	}
}
