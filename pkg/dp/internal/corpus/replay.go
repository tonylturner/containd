// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

type PositionMode uint8

const (
	Sequence PositionMode = iota
	SessionOffsets
)

type ReplayOptions struct {
	Position   PositionMode
	FailClosed bool // CloseStream acceptance; meaningful only for Kind == "close".
	// SimulateHandshake is an explicit test assumption, not conntrack evidence.
	// It sets TCPHandshake only on captured SYN/SYN-ACK records.
	SimulateHandshake bool
}

// Step records every inspection and lifecycle result, including errors and
// flow-end events. Kind is inspect, close, reset, end_session or flow_end.
type Step struct {
	Kind   string
	Packet Packet
	Result dpi.InspectResult
	Closed bool // CloseStream acceptance; meaningful only for Kind == "close".
}

// Replay invokes makeManager exactly once; it must construct a fresh Manager
// AND fresh decoders. Capture time updates flow counters, never the wall clock.
// Result errors are observations in Steps, not helper errors. All sessions and
// directional flows are ended, even with an incomplete EOF tail.
func Replay(makeManager func() *dpi.Manager, f Fixture, opts ReplayOptions) ([]Step, error) {
	if makeManager == nil || (opts.Position != Sequence && opts.Position != SessionOffsets) || len(f.Packets) == 0 {
		return nil, fmt.Errorf("invalid replay constructor, position or empty fixture")
	}
	inputs := make([]dpi.ParsedPacket, len(f.Packets))
	last := map[string]int{}
	for i, p := range f.Packets {
		if p.Connection == "" || p.Dir != dpi.ClientToServer && p.Dir != dpi.ServerToClient {
			return nil, fmt.Errorf("packet %d lacks connection/direction", i)
		}
		d := p.Decoded
		if d.Transport != "tcp" && d.Transport != "udp" {
			return nil, fmt.Errorf("packet %d invalid transport", i)
		}
		in := dpi.ParsedPacket{Payload: append([]byte(nil), d.Payload...), Proto: d.Transport, SrcPort: d.SrcPort, DstPort: d.DstPort, Dir: p.Dir, FailClosed: opts.FailClosed}
		if d.Transport == "tcp" {
			if !d.TCP.Valid {
				return nil, fmt.Errorf("packet %d lacks sequence metadata", i)
			}
			in.TCPSeqValid = true
			in.TCPSeq = d.TCP.Seq
			in.TCPSyn = d.TCP.Flags&capture.TCPFlagSYN != 0
			in.TCPFin = d.TCP.Flags&capture.TCPFlagFIN != 0
			in.TCPRst = d.TCP.Flags&capture.TCPFlagRST != 0
			if in.TCPSyn {
				in.TCPSeq++
			}
			in.TCPHandshake = in.TCPSyn && opts.SimulateHandshake
			if opts.Position == SessionOffsets {
				if !p.HasOrigin {
					return nil, fmt.Errorf("packet %d lacks offset anchor", i)
				}
				delta := int64(int32(in.TCPSeq - p.Origin))
				if delta < 0 || delta > 1<<30 {
					return nil, fmt.Errorf("packet %d ambiguous/out-of-range sequence offset", i)
				}
				in.HasOffset = true
				in.Offset = delta
				in.Session = p.Connection
			}
		}
		inputs[i] = in
		last[p.Connection] = i
	}
	m := makeManager()
	if m == nil {
		return nil, fmt.Errorf("constructor returned nil Manager")
	}
	var steps []Step
	states := map[string]map[dpi.StreamDir]*flow.State{}
	// Track the last source packet for accurate cleanup provenance.
	recent := map[string]map[dpi.StreamDir]Packet{}
	for i, p := range f.Packets {
		dirs := states[p.Connection]
		if dirs == nil {
			dirs = map[dpi.StreamDir]*flow.State{}
			states[p.Connection] = dirs
			recent[p.Connection] = map[dpi.StreamDir]Packet{}
		}
		state := dirs[p.Dir]
		if state == nil {
			dir := flow.DirForward
			if p.Dir == dpi.ServerToClient {
				dir = flow.DirReverse
			}
			d := p.Decoded
			state = flow.NewState(flow.Key{SrcIP: d.SrcIP, DstIP: d.DstIP, SrcPort: d.SrcPort, DstPort: d.DstPort, Proto: d.Proto, Dir: dir}, p.Time)
			dirs[p.Dir] = state
		}
		state.Touch(uint64(len(p.Decoded.Payload)), p.Time)
		recent[p.Connection][p.Dir] = p
		in := inputs[i]
		steps = append(steps, Step{Kind: "inspect", Packet: p, Result: m.Inspect(state, &in)})
		if opts.Position == Sequence && (in.TCPFin || in.TCPRst) {
			ended, events, err := m.CloseStream(state, &in)
			steps = append(steps, Step{Kind: "close", Packet: p, Closed: ended, Result: dpi.InspectResult{Events: events, Err: err}})
			if ended && in.TCPRst {
				peerDir := dpi.ClientToServer
				if p.Dir == peerDir {
					peerDir = dpi.ServerToClient
				}
				if peer := dirs[peerDir]; peer != nil {
					events, err := m.ResetStream(peer, &in)
					steps = append(steps, Step{Kind: "reset", Packet: recent[p.Connection][peerDir], Result: dpi.InspectResult{Events: events, Err: err}})
				}
			}
		}
		if last[p.Connection] == i {
			if opts.Position == SessionOffsets && p.Decoded.Transport == "tcp" {
				m.EndStream(p.Connection)
				steps = append(steps, Step{Kind: "end_session", Packet: p})
			}
			for _, dir := range []dpi.StreamDir{dpi.ClientToServer, dpi.ServerToClient} {
				if s := dirs[dir]; s != nil {
					events, err := m.OnFlowEnd(s)
					steps = append(steps, Step{Kind: "flow_end", Packet: recent[p.Connection][dir], Result: dpi.InspectResult{Events: events, Err: err}})
				}
			}
			delete(states, p.Connection)
			delete(recent, p.Connection)
		}
	}
	return steps, nil
}
