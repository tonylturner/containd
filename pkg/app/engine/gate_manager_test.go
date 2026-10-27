// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// gateTestAdmitter records every admission switch and reports them on a channel.
type gateTestAdmitter struct {
	states chan enforce.GateAdmitState
	err    atomic.Pointer[error]
}

func newGateTestAdmitter() *gateTestAdmitter {
	return &gateTestAdmitter{states: make(chan enforce.GateAdmitState, 64)}
}

func (a *gateTestAdmitter) SetGateAdmit(_ context.Context, s enforce.GateAdmitState) error {
	a.states <- s
	if err := a.err.Load(); err != nil {
		return *err
	}
	return nil
}

// await returns once want has been applied, failing on any other state
// first only when strict.
func (a *gateTestAdmitter) await(t *testing.T, want enforce.GateAdmitState) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-a.states:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("admission %s not applied", want)
		}
	}
}

// gateTestScanner is ready on demand and finds every object clean.
type gateTestScanner struct{ ready atomic.Bool }

func (s *gateTestScanner) Ready() (bool, string) {
	if s.ready.Load() {
		return true, ""
	}
	return false, "starting"
}

func (s *gateTestScanner) Scan(context.Context, avscan.Object) avscan.Result {
	return avscan.Result{Verdict: avscan.Clean, Backend: "test"}
}

// gateTestEnv runs a manager on plain loopback sockets: the listeners bind
// ephemeral ports, the dialer is a plain dialer that records its marks,
// the effective destination is the test's upstream and routing is counted.
type gateTestEnv struct {
	g       *gateManager
	admit   *gateTestAdmitter
	scanner *gateTestScanner
	store   *events.Store

	mu        sync.Mutex
	listeners []net.Listener
	marks     []uint32
	upstream  netip.AddrPort
	original  netip.AddrPort
	ensured   int
	removed   int
}

func newGateTestEnv(t *testing.T) *gateTestEnv {
	t.Helper()
	env := &gateTestEnv{admit: newGateTestAdmitter(), scanner: &gateTestScanner{}, store: events.NewStore(256)}
	env.scanner.ready.Store(true)
	g := newGateManager(zap.NewNop().Sugar(), env.scanner, env.admit, env.store, 0, 0)
	g.listen = func(ctx context.Context, network, address string) (net.Listener, error) {
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, network, address)
		if err != nil {
			return nil, err
		}
		env.mu.Lock()
		env.listeners = append(env.listeners, ln)
		env.mu.Unlock()
		return ln, nil
	}
	g.dial = func(ctx context.Context, network string, _ netip.Addr, mark uint32, server netip.AddrPort) (*net.TCPConn, error) {
		env.mu.Lock()
		env.marks = append(env.marks, mark)
		env.mu.Unlock()
		var d net.Dialer
		c, err := d.DialContext(ctx, network, server.String())
		if err != nil {
			return nil, err
		}
		return c.(*net.TCPConn), nil
	}
	g.originalDst = func(*net.TCPConn) (netip.AddrPort, error) {
		env.mu.Lock()
		defer env.mu.Unlock()
		if !env.original.IsValid() {
			return netip.AddrPort{}, errors.New("no conntrack")
		}
		return env.original, nil
	}
	g.effectiveDst = func(*net.TCPConn) netip.AddrPort {
		env.mu.Lock()
		defer env.mu.Unlock()
		return env.upstream
	}
	g.ensureRouting = func(context.Context) error {
		env.mu.Lock()
		defer env.mu.Unlock()
		env.ensured++
		return nil
	}
	g.removeRouting = func(context.Context) error {
		env.mu.Lock()
		defer env.mu.Unlock()
		env.removed++
		return nil
	}
	g.fwmarkAccept = func() (bool, error) { return false, nil }
	env.g = g
	t.Cleanup(g.close)
	return env
}

// listener returns the i-th listener's bound address once it is up.
func (env *gateTestEnv) listener(t *testing.T, i int) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := env.g.status()
		if i < len(st.Listeners) && st.Listeners[i].Up {
			return st.Listeners[i].Address
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener %d not up: %+v", i, st.Listeners)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (env *gateTestEnv) closeListener(t *testing.T, address string) {
	t.Helper()
	env.mu.Lock()
	defer env.mu.Unlock()
	for _, ln := range env.listeners {
		if ln.Addr().String() == address {
			ln.Close()
			return
		}
	}
	t.Fatalf("listener %s not found", address)
}

func (env *gateTestEnv) dialMarks() []uint32 {
	env.mu.Lock()
	defer env.mu.Unlock()
	return append([]uint32(nil), env.marks...)
}

func TestGateManagerAdmissionFollowsListenersAndPolicy(t *testing.T) {
	env := newGateTestEnv(t)
	g := env.g
	if st := g.status(); st.State != "off" || st.Admit != "refuse" {
		t.Fatalf("initial status %+v", st)
	}
	g.setEnforcing(true)
	// Fail-open by default: selected connections pass until the gate is up.
	env.admit.await(t, enforce.GateAdmitPass)
	env.admit.await(t, enforce.GateAdmitOpen)
	st := g.status()
	if st.State != "open" || len(st.Listeners) != 4 || !st.Scanner.Ready {
		t.Fatalf("status after start %+v", st)
	}
	for _, l := range st.Listeners {
		if !l.Up || l.Error != "" {
			t.Fatalf("listener %+v", l)
		}
	}
	if st.Listeners[0].Masquerade || !st.Listeners[2].Masquerade {
		t.Fatalf("masquerade flags %+v", st.Listeners)
	}
	g.setEnforcing(true) // idempotent
	select {
	case s := <-env.admit.states:
		t.Fatalf("second start switched admission to %s", s)
	case <-time.After(50 * time.Millisecond):
	}

	g.applyAV(config.AVConfig{Enabled: true, FailPolicy: "closed", HTTPDownload: true})
	if st := g.status(); st.FailPolicy != "closed" || st.State != "open" {
		t.Fatalf("status after closed policy %+v", st)
	}
	env.closeListener(t, env.listener(t, 0))
	env.admit.await(t, enforce.GateAdmitRefuse)
	env.admit.await(t, enforce.GateAdmitOpen)

	g.applyAV(config.AVConfig{Enabled: true, FailPolicy: "open", HTTPDownload: true})
	env.closeListener(t, env.listener(t, 3))
	env.admit.await(t, enforce.GateAdmitPass)
	env.admit.await(t, enforce.GateAdmitOpen)

	env.scanner.ready.Store(false)
	if st := g.status(); st.State != "pending" || st.Scanner.Error != "starting" {
		t.Fatalf("status with scanner starting %+v", st)
	}
	g.applySnapshot(rules.GateSelection{Enabled: true})
	if st := g.status(); !st.Enabled {
		t.Fatal("selection not reported")
	}

	g.setEnforcing(false)
	if st := g.status(); st.State != "off" || len(st.Listeners) != 0 {
		t.Fatalf("status after stop %+v", st)
	}
	env.mu.Lock()
	ensured, removed := env.ensured, env.removed
	env.mu.Unlock()
	if ensured != 1 || removed != 1 {
		t.Fatalf("routing ensured %d times and removed %d times", ensured, removed)
	}
	g.setEnforcing(false)
	env.mu.Lock()
	removed = env.removed
	env.mu.Unlock()
	if removed != 1 {
		t.Fatalf("second stop removed routing again (%d)", removed)
	}
	kinds := 0
	for _, ev := range env.store.List(100) {
		if ev.Kind == gateEventState {
			kinds++
		}
	}
	if kinds == 0 {
		t.Fatal("no admission events recorded")
	}
}

func TestGateManagerReportsAdmitterFailure(t *testing.T) {
	env := newGateTestEnv(t)
	failure := errors.New("nft: gate_admit missing")
	env.admit.err.Store(&failure)
	env.g.setEnforcing(true)
	env.admit.await(t, enforce.GateAdmitOpen)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if st := env.g.status(); st.AdmitError == failure.Error() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("admitter failure not reported: %+v", env.g.status())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGateManagerProxiesWithMarksAndEvents(t *testing.T) {
	env := newGateTestEnv(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Target", r.URL.Path)
		_, _ = io.WriteString(w, "hello from upstream")
	}))
	t.Cleanup(upstream.Close)
	env.mu.Lock()
	env.upstream = netip.MustParseAddrPort(strings.TrimPrefix(upstream.URL, "http://"))
	env.original = netip.MustParseAddrPort("203.0.113.9:8080")
	env.mu.Unlock()
	env.g.applyAV(config.AVConfig{Enabled: true, HTTPDownload: true})
	env.g.setEnforcing(true)
	env.admit.await(t, enforce.GateAdmitOpen)

	get := func(address, path string) string {
		t.Helper()
		c, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: files.example\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Target") != path {
			t.Fatalf("response %d %v", resp.StatusCode, resp.Header)
		}
		return string(body)
	}
	if body := get(env.listener(t, 0), "/plain"); body != "hello from upstream" {
		t.Fatalf("body %q", body)
	}
	if body := get(env.listener(t, 2), "/masq"); body != "hello from upstream" {
		t.Fatalf("body %q", body)
	}
	marks := env.dialMarks()
	if len(marks) != 2 || marks[0] != enforce.GateUpstreamSockMark || marks[1] != enforce.GateUpstreamSockMark|enforce.GateMasqSockMark {
		t.Fatalf("upstream marks %#x", marks)
	}
	var scanned []events.Event
	for _, ev := range env.store.List(100) {
		if ev.Kind == gateEventScanned {
			scanned = append(scanned, ev)
		}
	}
	if len(scanned) != 2 {
		t.Fatalf("scanned events %+v", scanned)
	}
	for _, ev := range scanned {
		if ev.Attributes["original_destination"] != "203.0.113.9:8080" || ev.Attributes["verdict"] != "clean" || ev.Attributes["action"] != "deliver" || ev.Attributes["backend"] != "test" || ev.SrcIP != "127.0.0.1" {
			t.Fatalf("event %+v", ev)
		}
		if ev.Attributes["server"] != env.upstream.String() {
			t.Fatalf("event server %v, want %s", ev.Attributes["server"], env.upstream)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for env.g.registry.count() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d connections still registered after close", env.g.registry.count())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGateManagerCloseMatchingResetsBothLegs(t *testing.T) {
	env := newGateTestEnv(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		if _, err := http.ReadRequest(r); err != nil {
			serverErr <- err
			return
		}
		// Hold the request: the gate must reset this leg too.
		_, err = r.ReadByte()
		serverErr <- err
	}()
	env.mu.Lock()
	env.upstream = gateAddrPort(ln.Addr())
	env.mu.Unlock()
	env.g.setEnforcing(true)
	env.admit.await(t, enforce.GateAdmitOpen)

	c, err := net.Dial("tcp4", env.listener(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "GET /held HTTP/1.1\r\nHost: files.example\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		entry := env.g.registry.lookup(gateAddrPort(c.LocalAddr()))
		if entry != nil && len(entry.legs()) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("upstream leg not registered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := env.g.CloseMatching(engine.GateCloseRequest{Host: netip.MustParseAddr("192.0.2.1")}); n != 0 {
		t.Fatalf("closed %d connections for an unrelated host", n)
	}
	if n := env.g.CloseMatching(engine.GateCloseRequest{Host: netip.MustParseAddr("127.0.0.1")}); n != 1 {
		t.Fatalf("closed %d connections, want 1", n)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("client leg still open")
	}
	select {
	case err := <-serverErr:
		if err == nil {
			t.Fatal("upstream leg still open")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream leg not reset")
	}
	if n := env.g.registry.count(); n != 0 {
		t.Fatalf("%d connections registered after reset", n)
	}
	if n := (*gateManager)(nil).CloseMatching(engine.GateCloseRequest{Host: netip.MustParseAddr("127.0.0.1")}); n != 0 {
		t.Fatal("nil manager closed connections")
	}
}

func TestGateFollowerRunsGateWithEnforcement(t *testing.T) {
	env := newGateTestEnv(t)
	dp, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	follower := gateFollower{Engine: dp, gate: env.g}
	fresh, err := engine.New(engine.Config{Events: dp.Events()})
	if err != nil {
		t.Fatal(err)
	}
	if err := follower.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	if st := env.g.status(); st.State != "off" {
		t.Fatalf("gate running without enforcement: %+v", st)
	}
}
