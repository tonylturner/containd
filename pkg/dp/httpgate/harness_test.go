// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// infectedMarker inside a body makes the fake scanner report Infected.
const infectedMarker = "CONTAIND-TEST-MARKER-INFECTED"

const testSignature = "Test.Marker"

// fakeScanner is a Scanner that can be held, made not ready, or given a
// scripted verdict. It records every call with the body bytes it read.
type fakeScanner struct {
	mu          sync.Mutex
	notReady    string
	verdict     func(obj avscan.Object, body []byte) avscan.Result
	hold        chan struct{}
	calls       []scanCall
	scanStarted chan struct{}
}

type scanCall struct {
	obj    avscan.Object
	body   []byte
	ctxErr error
}

func newFakeScanner() *fakeScanner {
	return &fakeScanner{scanStarted: make(chan struct{}, 64)}
}

func (f *fakeScanner) Ready() (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.notReady == "", f.notReady
}

func (f *fakeScanner) setNotReady(reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notReady = reason
}

func (f *fakeScanner) setVerdict(v func(obj avscan.Object, body []byte) avscan.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verdict = v
}

// holdScans makes every Scan that starts from now block until the
// returned release runs or the context ends. Calling it again installs a
// fresh latch for later scans, so one transaction's upload and download
// can be released separately.
func (f *fakeScanner) holdScans() (release func()) {
	ch := make(chan struct{})
	f.mu.Lock()
	f.hold = ch
	f.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

func (f *fakeScanner) Scan(ctx context.Context, obj avscan.Object) avscan.Result {
	body := make([]byte, obj.Size)
	if _, err := io.ReadFull(io.NewSectionReader(obj.Body, 0, obj.Size), body); err != nil {
		return avscan.Result{Verdict: avscan.Unscanned, Reason: avscan.ReasonScannerError, Backend: "fake", Detail: err.Error()}
	}
	f.mu.Lock()
	hold, verdict := f.hold, f.verdict
	f.mu.Unlock()
	f.scanStarted <- struct{}{}
	var ctxErr error
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			ctxErr = ctx.Err()
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, scanCall{obj: obj, body: body, ctxErr: ctxErr})
	f.mu.Unlock()
	switch {
	case ctxErr != nil:
		return avscan.Result{Verdict: avscan.Unscanned, Reason: avscan.ReasonTimeout, Backend: "fake", Detail: ctxErr.Error()}
	case verdict != nil:
		return verdict(obj, body)
	case bytes.Contains(body, []byte(infectedMarker)):
		return avscan.Result{Verdict: avscan.Infected, Signature: testSignature, Backend: "fake"}
	}
	return avscan.Result{Verdict: avscan.Clean, Backend: "fake"}
}

func (f *fakeScanner) scanCalls() []scanCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]scanCall(nil), f.calls...)
}

// waitScanStarted blocks until a Scan call has read its body and reached
// the verdict point.
func (f *fakeScanner) waitScanStarted(t *testing.T) {
	t.Helper()
	select {
	case <-f.scanStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner was not called")
	}
}

// recorder captures every byte read from a connection and counts
// connections, for assertions on what a peer actually received.
type recorder struct {
	mu       sync.Mutex
	accepted int
	data     bytes.Buffer
}

func (r *recorder) wrap(c net.Conn) net.Conn {
	r.mu.Lock()
	r.accepted++
	r.mu.Unlock()
	return &recConn{Conn: c, rec: r}
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.data.Bytes()...)
}

func (r *recorder) connections() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.accepted
}

type recConn struct {
	net.Conn
	rec *recorder
}

func (c *recConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rec.mu.Lock()
		c.rec.data.Write(p[:n])
		c.rec.mu.Unlock()
	}
	return n, err
}

func (c *recConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type recListener struct {
	net.Listener
	rec *recorder
}

func (l *recListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.rec.wrap(c), nil
}

// origin is a loopback server standing in for the real destination. dst,
// when set, replaces the OriginalDst hook that would return addr; dial,
// when set, is installed as the Dial hook.
type origin struct {
	addr netip.AddrPort
	rec  *recorder
	dst  func(net.Conn) (netip.AddrPort, error)
	dial func(ctx context.Context, client, server netip.AddrPort) (net.Conn, error)
}

func listenLoopback(t *testing.T) (net.Listener, netip.AddrPort) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln, netip.MustParseAddrPort(ln.Addr().String())
}

// httpOrigin serves h with net/http, an independent HTTP/1.1
// implementation that validates the gate's output framing.
func httpOrigin(t *testing.T, h http.Handler) *origin {
	t.Helper()
	ln, addr := listenLoopback(t)
	rec := &recorder{}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(&recListener{Listener: ln, rec: rec}) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = srv.Close()
	})
	return &origin{addr: addr, rec: rec}
}

// rawOrigin runs handle on every accepted connection; conn counts from 1.
func rawOrigin(t *testing.T, handle func(c net.Conn, conn int)) *origin {
	t.Helper()
	ln, addr := listenLoopback(t)
	rec := &recorder{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			rc := rec.wrap(c)
			go func() {
				defer rc.Close()
				handle(rc, rec.connections())
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return &origin{addr: addr, rec: rec}
}

// echoOrigin records the request and answers 200 "ok" with the body
// echoed in X-Body-SHA256 and the framing in X-Framing.
func echoOrigin(t *testing.T, got *bodyLog) *origin {
	return httpOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			got.record(r, nil, err)
			return
		}
		got.record(r, body, nil)
		w.Header().Set("X-Body-SHA256", sha256hex(body))
		w.Header().Set("X-Framing", framingOf(r))
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "ok")
	}))
}

func framingOf(r *http.Request) string {
	if len(r.TransferEncoding) > 0 {
		return strings.Join(r.TransferEncoding, ",")
	}
	return fmt.Sprintf("length=%d", r.ContentLength)
}

// bodyLog collects what an http origin received.
type bodyLog struct {
	mu      sync.Mutex
	entries []bodyEntry
}

type bodyEntry struct {
	method, path string
	header       http.Header
	body         []byte
	err          error
	framing      string
}

func (l *bodyLog) record(r *http.Request, body []byte, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, bodyEntry{
		method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: body, err: err, framing: framingOf(r),
	})
}

func (l *bodyLog) list() []bodyEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]bodyEntry(nil), l.entries...)
}

// eventLog collects gate events. panicNext makes the next delivery
// panic instead, to prove the hook is isolated.
type eventLog struct {
	ch        chan Event
	panicNext atomic.Bool
}

func newEventLog() *eventLog { return &eventLog{ch: make(chan Event, 256)} }

func (l *eventLog) add(ev Event) {
	if l.panicNext.Swap(false) {
		panic("hook exploded on " + string(ev.Direction))
	}
	l.ch <- ev
}

// next returns the next event, failing after 5 s.
func (l *eventLog) next(t *testing.T) Event {
	t.Helper()
	select {
	case ev := <-l.ch:
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
		return Event{}
	}
}

// expectNone fails when an event arrives within d.
func (l *eventLog) expectNone(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case ev := <-l.ch:
		t.Fatalf("unexpected event %+v", ev)
	case <-time.After(d):
	}
}

// gate is a Server under test.
type gate struct {
	t        *testing.T
	srv      *Server
	addr     netip.AddrPort
	scanner  *fakeScanner
	events   *eventLog
	spoolDir string
	shutOnce sync.Once
}

// testSettings are generous defaults individual tests tighten.
func testSettings(spoolDir string) Settings {
	return Settings{
		ScanUploads:          true,
		ScanDownloads:        true,
		MaxObjectBytes:       8 << 20,
		FailPolicy:           avscan.FailClosed,
		SpoolDir:             spoolDir,
		MemoryThreshold:      64 << 10,
		MaxConnections:       64,
		MaxConcurrentObjects: 8,
		IdleTimeout:          5 * time.Second,
		ObjectTimeout:        10 * time.Second,
		DialTimeout:          5 * time.Second,
		ScanTimeout:          5 * time.Second,
	}
}

// startGate serves a gate whose OriginalDst is o. adjust edits the
// default settings before Update.
func startGate(t *testing.T, o *origin, adjust func(*Settings)) *gate {
	t.Helper()
	dir := t.TempDir()
	set := testSettings(dir)
	if adjust != nil {
		adjust(&set)
	}
	g := &gate{t: t, scanner: newFakeScanner(), events: newEventLog(), spoolDir: dir}
	dst := o.dst
	if dst == nil {
		dst = func(net.Conn) (netip.AddrPort, error) { return o.addr, nil }
	}
	g.srv = &Server{Scanner: g.scanner, OriginalDst: dst, Dial: o.dial, OnEvent: g.events.add}
	if err := g.srv.Update(set); err != nil {
		t.Fatal(err)
	}
	ln, addr := listenLoopback(t)
	g.addr = addr
	serveErr := make(chan error, 1)
	go func() { serveErr <- g.srv.Serve(ln) }()
	t.Cleanup(func() {
		g.shutdown(5 * time.Second)
		if err := <-serveErr; !errors.Is(err, ErrServerClosed) {
			t.Errorf("Serve returned %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Error(err)
		}
		for _, e := range entries {
			t.Errorf("spool file left behind: %s", e.Name())
		}
	})
	return g
}

func (g *gate) shutdown(within time.Duration) error {
	var err error
	g.shutOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), within)
		defer cancel()
		err = g.srv.Shutdown(ctx)
	})
	return err
}

// dial opens a recorded client connection to the gate.
func (g *gate) dial() (net.Conn, *recorder) {
	g.t.Helper()
	c, err := net.Dial("tcp", g.addr.String())
	if err != nil {
		g.t.Fatal(err)
	}
	g.t.Cleanup(func() { c.Close() })
	rec := &recorder{}
	return rec.wrap(c), rec
}

// client is one connection to the gate with a response reader.
type client struct {
	t    *testing.T
	conn net.Conn
	rec  *recorder
	br   *bufio.Reader
}

func (g *gate) client() *client {
	c, rec := g.dial()
	return &client{t: g.t, conn: c, rec: rec, br: bufio.NewReader(c)}
}

func (c *client) write(b []byte) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatalf("client write: %v", err)
	}
}

// response reads one response for a request made with method and returns
// it with the body consumed.
func (c *client) response(method string) (*http.Response, []byte) {
	c.t.Helper()
	resp, body, err := c.tryResponse(method)
	if err != nil {
		c.t.Fatalf("client read response: %v", err)
	}
	return resp, body
}

func (c *client) tryResponse(method string) (*http.Response, []byte, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(c.br, &http.Request{Method: method})
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body, err
}

// expectEOF asserts that the gate closed the connection.
func (c *client) expectEOF() {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.br.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, io.EOF) {
		c.t.Fatalf("expected EOF from gate, got n=%d err=%v", n, err)
	}
}

// expectSilence asserts that nothing arrives from the gate within d, with
// a deadline-bounded socket read rather than a look at the recorder, which
// only sees bytes once something reads them.
func (c *client) expectSilence(d time.Duration) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(d))
	n, err := c.conn.Read(make([]byte, 1))
	if n != 0 || !isTimeout(err) {
		c.t.Fatalf("expected nothing from the gate within %v, got n=%d err=%v", d, n, err)
	}
}

// expectClosed asserts that the gate ended the connection, by FIN or by
// reset when the client was still sending.
func (c *client) expectClosed() {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.br.Read(make([]byte, 1))
	if n != 0 || err == nil || isTimeout(err) {
		c.t.Fatalf("expected the gate to close, got n=%d err=%v", n, err)
	}
}

// pattern is deterministic pseudo-random content of n bytes.
func pattern(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// requestCL builds a Content-Length request.
func requestCL(method, path string, extra string, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: origin.test\r\nContent-Length: %d\r\n%s\r\n", method, path, len(body), extra)
	b.Write(body)
	return b.Bytes()
}

// requestChunked builds a chunked request in chunks of size bytes.
func requestChunked(method, path string, extra string, body []byte, size int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n%s\r\n", method, path, extra)
	b.Write(chunked(body, size))
	return b.Bytes()
}

// chunked encodes body as chunks of size bytes with the last chunk.
func chunked(body []byte, size int) []byte {
	var b bytes.Buffer
	for len(body) > 0 {
		n := min(size, len(body))
		fmt.Fprintf(&b, "%x\r\n", n)
		b.Write(body[:n])
		b.WriteString("\r\n")
		body = body[n:]
	}
	b.WriteString("0\r\n\r\n")
	return b.Bytes()
}

func getRequest(path, extra string) []byte {
	return []byte("GET " + path + " HTTP/1.1\r\nHost: origin.test\r\n" + extra + "\r\n")
}

// readRequestHead reads one request head from a raw origin connection.
func readRequestHead(c net.Conn) ([]byte, *bufio.Reader, error) {
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	raw, err := readHead(br)
	return raw, br, err
}

// readFullBody consumes a request body described by head from br.
func readFullBody(head []byte, br *bufio.Reader) ([]byte, error) {
	h, err := parseRequestHead(head)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(newBodyReader(h, br))
}

// expectEvent asserts the main fields of an object event.
func expectEvent(t *testing.T, ev Event, dir avscan.Direction, verdict avscan.Verdict, reason avscan.Reason, action avscan.Action) {
	t.Helper()
	if ev.Direction != dir || ev.Verdict != verdict || ev.Reason != reason || ev.Action != action {
		t.Fatalf("event %s/%s/%s/%s, want %s/%s/%s/%s (detail %q error %q)",
			ev.Direction, ev.Verdict, ev.Reason, ev.Action, dir, verdict, reason, action, ev.Detail, ev.Error)
	}
}

// eventually retries cond until it holds or 5 s pass.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
