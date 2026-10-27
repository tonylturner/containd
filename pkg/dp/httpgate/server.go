// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

// Package httpgate serves HTTP/1.x connections steered to it, holds each
// selected message body until a scanner has classified it, and delivers or
// refuses the whole message afterwards. No byte of a selected message
// reaches its recipient before the decision; interim 1xx responses are the
// only exception. Steering, scanner backends and configuration live
// elsewhere and arrive through hooks.
package httpgate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// ErrServerClosed is returned by Serve after Shutdown.
var ErrServerClosed = errors.New("httpgate: server closed")

// Server is the object gate. Set the hooks, call Update with the initial
// Settings, then Serve one or more listeners.
type Server struct {
	// Scanner classifies held bodies.
	Scanner avscan.Scanner
	// OriginalDst returns the destination the client meant to reach.
	OriginalDst func(net.Conn) (netip.AddrPort, error)
	// Dial opens the upstream connection; nil uses net.Dialer.
	Dial func(ctx context.Context, client, server netip.AddrPort) (net.Conn, error)
	// OnEvent receives every Event synchronously; nil discards them.
	OnEvent func(Event)

	settings atomic.Pointer[Settings]
	initOnce sync.Once
	ctx      context.Context
	cancel   context.CancelFunc
	prefix   string

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     map[*conn]struct{}
	closing   bool
	wg        sync.WaitGroup

	connSeq     atomic.Int64
	activeConns atomic.Int64
	heldObjects atomic.Int64
	// refusedConns counts connections closed over MaxConnections;
	// reportedRefusals and lastRefusalReport bound how often they are
	// reported.
	refusedConns      atomic.Int64
	reportedRefusals  atomic.Int64
	lastRefusalReport atomic.Int64
}

// refusalReportInterval bounds how often refused connections are reported.
const refusalReportInterval = time.Second

func (s *Server) init() {
	s.initOnce.Do(func() {
		s.ctx, s.cancel = context.WithCancel(context.Background())
		s.listeners = map[net.Listener]struct{}{}
		s.conns = map[*conn]struct{}{}
		var b [4]byte
		_, _ = rand.Read(b[:])
		s.prefix = hex.EncodeToString(b[:])
	})
}

// Update validates and installs new settings. On error the previous
// settings stay in force. Transactions already in flight keep the
// snapshot they started with.
func (s *Server) Update(set Settings) error {
	if err := set.validate(); err != nil {
		return err
	}
	s.settings.Store(&set)
	return nil
}

// Serve accepts connections on l until Shutdown or an accept error. It
// returns ErrServerClosed after Shutdown.
func (s *Server) Serve(l net.Listener) error {
	s.init()
	if s.settings.Load() == nil {
		l.Close()
		return errors.New("httpgate: Serve before Update")
	}
	if s.Scanner == nil || s.OriginalDst == nil {
		l.Close()
		return errors.New("httpgate: Scanner and OriginalDst are required")
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		l.Close()
		return ErrServerClosed
	}
	s.listeners[l] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, l)
		s.mu.Unlock()
		l.Close()
	}()

	var delay time.Duration
	for {
		nc, err := l.Accept()
		if err != nil {
			if s.isClosing() {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				delay = max(5*time.Millisecond, min(2*delay, time.Second))
				select {
				case <-time.After(delay):
					continue
				case <-s.ctx.Done():
					return ErrServerClosed
				}
			}
			return err
		}
		delay = 0
		if !s.track(nc) {
			nc.Close()
			return ErrServerClosed
		}
	}
}

func (s *Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

// track registers nc and starts its handler; false after Shutdown. A
// connection over MaxConnections is refused before its reader or
// goroutine exists. The count covers a handler until it has exited, so
// connections draining after a refusal stay inside the bound.
func (s *Server) track(nc net.Conn) bool {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return false
	}
	set := s.settings.Load()
	if s.activeConns.Add(1) > int64(set.MaxConnections) {
		s.activeConns.Add(-1)
		s.mu.Unlock()
		s.refuseConnection(nc)
		return true
	}
	c := newConn(s, nc, set)
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer s.activeConns.Add(-1)
		defer s.untrack(c)
		c.serve()
	}()
	return true
}

// refuseConnection closes nc at once and reports the refusals since the
// last report, at most once per refusalReportInterval.
func (s *Server) refuseConnection(nc net.Conn) {
	var client netip.AddrPort
	if ap, err := netip.ParseAddrPort(nc.RemoteAddr().String()); err == nil {
		client = unmap(ap)
	}
	nc.Close()
	refused := s.refusedConns.Add(1)
	now := time.Now()
	last := s.lastRefusalReport.Load()
	if now.UnixNano()-last < int64(refusalReportInterval) || !s.lastRefusalReport.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	since := refused - s.reportedRefusals.Swap(refused)
	s.emit(Event{
		Time: now, Client: client, Action: avscan.Block,
		Error: fmt.Sprintf("connection limit reached: %d connections refused", since),
	})
}

func (s *Server) untrack(c *conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// Shutdown stops accepting, cancels scans in progress, closes idle
// connections and waits for the active ones to finish. When ctx ends
// first it closes every connection and returns ctx.Err() once their
// handlers have exited.
func (s *Server) Shutdown(ctx context.Context) error {
	s.init()
	s.mu.Lock()
	s.closing = true
	for l := range s.listeners {
		l.Close()
	}
	s.mu.Unlock()
	s.cancel()
	s.mu.Lock()
	for c := range s.conns {
		if c.idle() {
			c.closeAll()
		}
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
	}
	s.mu.Lock()
	for c := range s.conns {
		c.closeAll()
	}
	s.mu.Unlock()
	<-done
	return ctx.Err()
}

// acquireObject takes one of the limit object slots.
func (s *Server) acquireObject(limit int) bool {
	for {
		n := s.heldObjects.Load()
		if n >= int64(limit) {
			return false
		}
		if s.heldObjects.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (s *Server) releaseObject() { s.heldObjects.Add(-1) }

// emit delivers ev to OnEvent. A hook that panics loses that event and
// is reported through one more delivery; a hook that panics on that too
// is left alone.
func (s *Server) emit(ev Event) {
	if s.OnEvent == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if r := s.callHook(ev); r != nil {
		_ = s.callHook(Event{
			Time: time.Now(), ID: ev.ID, Client: ev.Client, Server: ev.Server, Action: avscan.Block,
			Error: fmt.Sprintf("OnEvent panic: %v", r),
		})
	}
}

// callHook runs OnEvent and returns what it panicked with, if anything.
func (s *Server) callHook(ev Event) (panicked any) {
	defer func() { panicked = recover() }()
	s.OnEvent(ev)
	return nil
}

// dial opens the upstream connection through the Dial hook.
func (s *Server) dial(ctx context.Context, client, server netip.AddrPort) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, client, server)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", server.String())
}

func (s *Server) nextConnID() string {
	return fmt.Sprintf("%s-%d", s.prefix, s.connSeq.Add(1))
}

// gateResult is an Unscanned result the gate produced without a backend.
func gateResult(reason avscan.Reason, detail string) avscan.Result {
	return avscan.Result{Verdict: avscan.Unscanned, Reason: reason, Backend: "gate", Detail: detail}
}
