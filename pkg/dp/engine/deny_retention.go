// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

const (
	deniedTCPLifetime = 10 * time.Second
	deniedTCPCapacity = 16384
)

var deniedTCPEvictions = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "containd",
	Subsystem: "dp",
	Name:      "denied_tcp_evictions_total",
	Help:      "TCP denial tombstones evicted before expiry to maintain the capacity bound.",
})

// rememberDeniedTCP inserts once, without refreshing the lifetime on duplicates.
// Insertions and the FIFO share flowMu, so concurrent denials cannot exceed the
// capacity. Retirement never holds flowMu while waiting for an in-flight reset.
func (e *Engine) rememberDeniedTCP(key, service flow.Key) *deniedTCP {
	tuple := tcpTupleKey(key)
	for {
		e.flowMu.Lock()
		now := e.deniedTCPNow()
		if d := e.deniedTCP[tuple]; d != nil {
			e.flowMu.Unlock()
			if now.Before(d.expires) {
				return nil
			}
			e.retireDeniedTCP(d, false)
			continue
		}
		if len(e.deniedTCP) >= deniedTCPCapacity {
			oldest := e.deniedTCPOrder.Front().Value.(*deniedTCP)
			e.flowMu.Unlock()
			e.retireDeniedTCP(oldest, now.Before(oldest.expires))
			continue
		}
		if e.deniedTCP == nil {
			e.deniedTCP = make(map[flow.MapKey]*deniedTCP)
		}
		opener := key
		if opener.Dir == flow.DirReverse {
			opener = opener.Reversed()
		}
		isn, hasISN := e.tcpISNs[opener.MapKey()]
		d := &deniedTCP{key: key, service: service, tuple: tuple, isn: isn, hasISN: hasISN, expires: now.Add(deniedTCPLifetime)}
		d.order = e.deniedTCPOrder.PushBack(d)
		e.deniedTCP[tuple] = d
		e.flowMu.Unlock()
		return d
	}
}

// expireDeniedTCP is a bounded FIFO pass in the existing flow sweep. A packet
// also expires its own tombstone lazily, so the 30-second sweep cadence does not
// extend the protection window. At most the hard capacity is examined per pass.
func (e *Engine) expireDeniedTCP(now time.Time) {
	for range deniedTCPCapacity {
		e.flowMu.Lock()
		first := e.deniedTCPOrder.Front()
		if first == nil {
			e.flowMu.Unlock()
			return
		}
		d := first.Value.(*deniedTCP)
		e.flowMu.Unlock()
		if now.Before(d.expires) {
			return
		}
		e.retireDeniedTCP(d, false)
	}
}

// retireDeniedTCP cancels old reset jobs and clears only this tuple's cache,
// flow and failed-stream state before publishing its absence. A late payload
// then has no anchored stream and fails closed as a pickup; a new handshake can
// anchor immediately. No second, longer-lived denial registry is needed.
//
// flowMu excludes trackFlow and isDeniedTCP during stream cleanup. In particular,
// an evicted tuple must not start inspection between removal and OnFlowEnd.
// Only decoder teardown runs under this lock; telemetry and reset I/O do not.
func (e *Engine) retireDeniedTCP(d *deniedTCP, eviction bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e.flowMu.Lock()
	if e.deniedTCP[d.tuple] != d {
		e.flowMu.Unlock()
		return
	}
	d.retired = true
	type endedFlow struct {
		state  *flow.State
		events []dpi.Event
	}
	var ended []endedFlow
	key := d.key
	key.Dir = flow.DirForward
	reverseOrientation := key
	reverseOrientation.Dir = flow.DirReverse
	for _, k := range []flow.Key{key, key.Reversed(), reverseOrientation, reverseOrientation.Reversed()} {
		e.verdictCache.Invalidate(k.Hash())
		st := e.dropFlowLocked(k)
		if st == nil {
			// A packet can have obtained its state just before another
			// tuple's capacity eviction forgot it. Its later pickup error
			// still needs teardown, even without a tracked flow entry.
			st = &flow.State{Key: k}
		}
		e.conformance.end(st, true)
		evs, _ := e.dpiMgr.OnFlowEnd(st)
		if len(evs) > 0 {
			ended = append(ended, endedFlow{st, evs})
		}
	}
	delete(e.deniedTCP, d.tuple)
	e.deniedTCPOrder.Remove(d.order)
	if eviction {
		deniedTCPEvictions.Inc()
	}
	e.flowMu.Unlock()
	for _, f := range ended {
		e.recordFlowEndEvents(f.state, nil, f.events)
	}
}
