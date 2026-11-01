// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/httpgate"
)

// The gate listens on loopback for each address family and each delivery
// port: the plain port and the port for connections whose upstream leg is
// masqueraded. A listener that cannot bind or stops accepting is bound
// again with backoff; meanwhile the admission follows the fail policy.

const (
	gateBindInitialBackoff = 200 * time.Millisecond
	gateBindMaxBackoff     = 5 * time.Second
)

// gateListener is one listener's supervision state; mu is the manager's.
type gateListener struct {
	network string
	address string
	masq    bool

	up    bool
	bound string // the bound address while up
	err   string
	// unavailable marks an address family this host does not have: its
	// listener is not required for delivery, as no such packets arrive.
	unavailable bool
}

func (l *gateListener) status() gateListenerStatus {
	address := l.address
	if l.up {
		address = l.bound
	}
	return gateListenerStatus{Address: address, Masquerade: l.masq, Up: l.up, Error: l.err, Unavailable: l.unavailable}
}

func (g *gateManager) newListeners() []*gateListener {
	var listeners []*gateListener
	for i, port := range g.ports {
		masq := i == 1
		p := strconv.Itoa(int(port))
		listeners = append(listeners,
			&gateListener{network: "tcp4", address: net.JoinHostPort("127.0.0.1", p), masq: masq},
			&gateListener{network: "tcp6", address: net.JoinHostPort("::1", p), masq: masq},
		)
	}
	return listeners
}

// listenersUpLocked reports whether every required listener accepts.
func (g *gateManager) listenersUpLocked() bool {
	for _, l := range g.listeners {
		if !l.up && !l.unavailable {
			return false
		}
	}
	return len(g.listeners) > 0
}

// run installs the routing and serves the listeners until ctx ends.
func (g *gateManager) run(ctx context.Context, srv *httpgate.Server, listeners []*gateListener, done chan struct{}) {
	defer close(done)
	var wg sync.WaitGroup
	wg.Add(2 + len(listeners))
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.publishProtection()
			}
		}
	}()
	go func() {
		defer wg.Done()
		g.installRouting(ctx)
	}()
	for _, l := range listeners {
		go func() {
			defer wg.Done()
			g.serveListener(ctx, srv, l)
		}()
	}
	wg.Wait()
}

// installRouting installs the local-delivery rule and route, retrying with
// backoff until it succeeds or ctx ends, and checks the sysctl once.
func (g *gateManager) installRouting(ctx context.Context) {
	g.checkFwmarkAccept()
	backoff := gateBindInitialBackoff
	for {
		err := g.ensureRouting(ctx)
		g.mu.Lock()
		g.routingOK = err == nil
		g.routingTerminal = gateUnsupported(err)
		prev := g.routingErr
		g.routingErr = ""
		if err != nil {
			g.routingErr = err.Error()
		}
		g.mu.Unlock()
		g.publishProtection()
		if err == nil {
			g.logger.Infof("gate routing installed")
			g.syncAdmit()
			return
		}
		if gateUnsupported(err) {
			g.logger.Errorf("gate routing: %v", err)
			return
		}
		// A failure that persists is reported once, not on every retry.
		if err.Error() != prev {
			g.logger.Errorf("gate routing (retrying): %v", err)
		}
		if !gateWait(ctx, backoff) {
			return
		}
		backoff = min(2*backoff, gateBindMaxBackoff)
	}
}

func (g *gateManager) checkFwmarkAccept() {
	on, err := g.fwmarkAccept()
	if err != nil {
		if !gateUnsupported(err) {
			g.logger.Warnf("gate: %v", err)
		}
		return
	}
	if !on {
		return
	}
	warning := "net.ipv4.tcp_fwmark_accept is enabled; the gate's replies would be routed back to it, set it to 0"
	g.mu.Lock()
	g.warning = warning
	g.mu.Unlock()
	g.logger.Warnf("gate: %s", warning)
	if g.events != nil {
		g.events.Append(events.Event{Proto: "av", Kind: gateEventState, Timestamp: time.Now().UTC(), Attributes: map[string]any{"warning": warning}})
	}
}

// serveListener binds l and serves it until ctx ends, binding again after
// a bind failure or an accept failure.
func (g *gateManager) serveListener(ctx context.Context, srv *httpgate.Server, l *gateListener) {
	backoff := gateBindInitialBackoff
	for ctx.Err() == nil {
		ln, err := g.listen(ctx, l.network, l.address)
		if err != nil {
			g.markListener(l, "", err)
			if !gateWait(ctx, backoff) {
				return
			}
			backoff = min(2*backoff, gateBindMaxBackoff)
			continue
		}
		backoff = gateBindInitialBackoff
		g.markListener(l, ln.Addr().String(), nil)
		err = srv.Serve(&gateAcceptor{Listener: ln, g: g, masq: l.masq})
		if ctx.Err() != nil || errors.Is(err, httpgate.ErrServerClosed) {
			g.markListener(l, "", nil)
			return
		}
		g.markListener(l, "", err)
		if !gateWait(ctx, backoff) {
			return
		}
	}
}

// markListener records l as up at bound, or down with err, and brings the
// admission in line. A change is logged; a failure that persists across
// retries is not repeated.
func (g *gateManager) markListener(l *gateListener, bound string, err error) {
	g.mu.Lock()
	wasUp, prevErr := l.up, l.err
	l.up, l.bound, l.err = bound != "", bound, ""
	l.unavailable = false
	if err != nil {
		l.err = err.Error()
		l.unavailable = errors.Is(err, syscall.EADDRNOTAVAIL)
	}
	changed := wasUp != l.up || prevErr != l.err
	g.mu.Unlock()
	switch {
	case !changed:
	case err != nil && l.unavailable:
		g.logger.Warnf("gate listener %s unavailable on this host: %v", l.address, err)
	case err != nil:
		g.logger.Errorf("gate listener %s down: %v", l.address, err)
	case l.up:
		g.logger.Infof("gate listener %s up", bound)
	}
	g.syncAdmit()
}

// gateAcceptor registers each accepted connection before the gate serves it.
type gateAcceptor struct {
	net.Listener
	g    *gateManager
	masq bool
}

func (a *gateAcceptor) Accept() (net.Conn, error) {
	for {
		c, err := a.Listener.Accept()
		if err != nil {
			return nil, err
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			c.Close()
			a.g.logger.Errorf("gate listener %s accepted %T, not TCP", a.Addr(), c)
			continue
		}
		entry := &gateEntry{client: gateAddrPort(tc.RemoteAddr()), effective: a.g.effectiveDst(tc), masq: a.masq, conn: tc}
		if original, err := a.g.originalDst(tc); err == nil {
			entry.original = original
		}
		a.g.registry.add(entry)
		return &gateConn{TCPConn: tc, reg: a.g.registry, entry: entry}, nil
	}
}

// gateUnsupported reports an operation this platform cannot perform.
func gateUnsupported(err error) bool {
	return errors.Is(err, errors.ErrUnsupported)
}

// gateWait sleeps d and reports false when ctx ended first.
func gateWait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
