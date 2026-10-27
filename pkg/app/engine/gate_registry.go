// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"net"
	"net/netip"
	"sync"

	"github.com/tonylturner/containd/pkg/dp/engine"
)

// gateRegistry holds every connection the gate carries by its two TCP legs,
// so a revocation or a block that covers the connection can reset both: the
// kernel rule stops the packets, but neither socket would learn of it.
type gateRegistry struct {
	mu      sync.Mutex
	entries map[gateKey]*gateEntry
}

type gateKey struct {
	client    netip.AddrPort
	effective netip.AddrPort
}

// gateEntry is one gated connection. The client leg runs from client to
// effective, the destination after DNAT that the listener accepted it for;
// original is the destination before DNAT, zero when unknown. The upstream
// leg runs from upstreamAddr, the client's address on a port the gate
// chose, to effective.
type gateEntry struct {
	client    netip.AddrPort
	effective netip.AddrPort
	original  netip.AddrPort
	masq      bool
	conn      *net.TCPConn

	mu           sync.Mutex
	upstream     *net.TCPConn
	upstreamAddr netip.AddrPort
}

func newGateRegistry() *gateRegistry {
	return &gateRegistry{entries: map[gateKey]*gateEntry{}}
}

func (r *gateRegistry) add(e *gateEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[gateKey{client: e.client, effective: e.effective}] = e
}

// remove forgets e; a newer entry under the same TCP tuple stays.
func (r *gateRegistry) remove(e *gateEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := gateKey{client: e.client, effective: e.effective}
	if r.entries[key] == e {
		delete(r.entries, key)
	}
}

func (r *gateRegistry) lookup(client, effective netip.AddrPort) *gateEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries[gateKey{client: client, effective: effective}]
}

func (r *gateRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// closeMatching resets both legs of every connection req matches and
// returns how many connections it reset. A reset connection is forgotten at
// once: it is dead, whether or not the gate has noticed yet.
func (r *gateRegistry) closeMatching(req engine.GateCloseRequest) int {
	r.mu.Lock()
	var matched []*gateEntry
	for key, e := range r.entries {
		if e.matches(req) {
			matched = append(matched, e)
			delete(r.entries, key)
		}
	}
	r.mu.Unlock()
	for _, e := range matched {
		e.reset()
	}
	return len(matched)
}

func (e *gateEntry) setUpstream(c *net.TCPConn, addr netip.AddrPort) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.upstream, e.upstreamAddr = c, addr
}

// clearUpstream forgets c when it is still the current upstream.
func (e *gateEntry) clearUpstream(c *net.TCPConn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.upstream == c {
		e.upstream, e.upstreamAddr = nil, netip.AddrPort{}
	}
}

// legs lists the tuples the connection is known by: the client leg by its
// effective and original destinations, and the upstream leg.
func (e *gateEntry) legs() [][2]netip.AddrPort {
	legs := [][2]netip.AddrPort{{e.client, e.effective}}
	if e.original.IsValid() && e.original != e.effective {
		legs = append(legs, [2]netip.AddrPort{e.client, e.original})
	}
	e.mu.Lock()
	up := e.upstreamAddr
	e.mu.Unlock()
	if up.IsValid() {
		legs = append(legs, [2]netip.AddrPort{up, e.effective})
	}
	return legs
}

func (e *gateEntry) matches(req engine.GateCloseRequest) bool {
	for _, leg := range e.legs() {
		if req.Host.IsValid() {
			if leg[0].Addr() == req.Host || leg[1].Addr() == req.Host {
				return true
			}
			continue
		}
		if gateTupleMatches(req, leg[0], leg[1]) || gateTupleMatches(req, leg[1], leg[0]) {
			return true
		}
	}
	return false
}

// gateTupleMatches reports whether req names the src→dst tuple; a zero
// port in req matches any port.
func gateTupleMatches(req engine.GateCloseRequest, src, dst netip.AddrPort) bool {
	return req.Src == src.Addr() && req.Dst == dst.Addr() &&
		(req.SrcPort == 0 || req.SrcPort == src.Port()) &&
		(req.DstPort == 0 || req.DstPort == dst.Port())
}

// reset closes both legs with a TCP reset, so each peer learns at once
// that its object is incomplete instead of waiting on a silent drop.
func (e *gateEntry) reset() {
	e.mu.Lock()
	up := e.upstream
	e.mu.Unlock()
	gateResetTCP(e.conn)
	if up != nil {
		gateResetTCP(up)
	}
}

func gateResetTCP(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}

// gateConn is an accepted client connection. Closing it forgets the
// connection; the embedded connection keeps SetLinger and CloseWrite, which
// the gate relies on to reset and half-close.
type gateConn struct {
	*net.TCPConn
	reg   *gateRegistry
	entry *gateEntry
	once  sync.Once
}

func (c *gateConn) Close() error {
	c.once.Do(func() { c.reg.remove(c.entry) })
	return c.TCPConn.Close()
}

// gateUpstreamConn is a dialled upstream connection; closing it forgets
// the upstream leg while the client leg lives on.
type gateUpstreamConn struct {
	*net.TCPConn
	entry *gateEntry
}

func (c *gateUpstreamConn) Close() error {
	c.entry.clearUpstream(c.TCPConn)
	return c.TCPConn.Close()
}

// gateAddrPort converts a TCP address; it is zero for anything else.
func gateAddrPort(a net.Addr) netip.AddrPort {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(tcp.Port))
}
