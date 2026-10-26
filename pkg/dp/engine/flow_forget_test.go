// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// endCounter is recordFramer counting the flow ends of each state, which
// end its streams in the reassembler.
type endCounter struct {
	recordFramer
	mu   sync.Mutex
	ends map[*flow.State]int
}

func (c *endCounter) OnFlowEnd(st *flow.State) ([]dpi.Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ends[st]++
	return nil, nil
}

func (c *endCounter) count(st *flow.State) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ends[st]
}

// TestForgottenFlowsEndTheirStreamsOnce checks that every flow the engine
// forgets ends its streams exactly once: one a handshake contradicts, as
// soon as it is dropped, and one that expires, at the sweep. Without the
// end, a failed or quiet fail-closed stream of the flow stays in the
// reassembler, which its idle sweep never removes.
func TestForgottenFlowsEndTheirStreamsOnce(t *testing.T) {
	e := recordEngine(t)
	counter := &endCounter{ends: map[*flow.State]int{}}
	e.dpiMgr = dpi.NewManager(counter)

	e.HandlePacket(recordPacket(100, capture.TCPFlagPSH, "AA"))
	reply := recordPacket(500, capture.TCPFlagPSH, "")
	reply.SrcIP, reply.DstIP, reply.SrcPort, reply.DstPort = reply.DstIP, reply.SrcIP, reply.DstPort, reply.SrcPort
	e.HandlePacket(reply)
	e.flowMu.Lock()
	var old []*flow.State
	for _, st := range e.flows {
		old = append(old, st)
	}
	e.flowMu.Unlock()
	if len(old) != 2 {
		t.Fatalf("tracked %d flow states, want both directions", len(old))
	}

	// A SYN-ACK from the side first seen as the opener: the tuple carries a
	// new connection, so both old directions are forgotten.
	e.HandlePacket(recordPacket(900, capture.TCPFlagSYN, ""))
	for _, st := range old {
		if got := counter.count(st); got != 1 {
			t.Fatalf("flow %s ended %d times at its drop, want once", st.Key.Hash(), got)
		}
	}
	e.flowMu.Lock()
	var current *flow.State
	for _, st := range e.flows {
		current = st
	}
	e.flowMu.Unlock()
	if current == nil || counter.count(current) != 0 {
		t.Fatalf("new connection state %+v ended before it expired", current)
	}

	e.sweepFlows(time.Now().Add(time.Hour))
	if got := counter.count(current); got != 1 {
		t.Fatalf("expired flow ended %d times at the sweep, want once", got)
	}
	for _, st := range old {
		if got := counter.count(st); got != 1 {
			t.Fatalf("dropped flow %s ended %d times in total, want once", st.Key.Hash(), got)
		}
	}
}
