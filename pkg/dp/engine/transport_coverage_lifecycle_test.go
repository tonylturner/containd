// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func TestTransportCoverageRetirement(t *testing.T) {
	for _, removal := range []string{"deny", "sweep"} {
		t.Run(removal, func(t *testing.T) {
			ev := natEvidence()
			ev.Reply = flow.TupleKey(ev.Original, flow.DirForward).Reversed().Tuple()
			e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
			r.authority.check(context.Background())
			at := time.Now()
			for _, tuple := range []conntrack.Tuple{ev.Original, ev.Reply} {
				r.admit(e, transportWire(tuple, at, nil))
				processTransportAdmission(t, e, r)
			}
			var states []*flow.State
			for st := range e.transportCoverage {
				states = append(states, st)
			}
			if len(states) != 2 {
				t.Fatalf("fixture tracked %d directional coverage entries, want two", len(states))
			}
			pkt := transportWire(ev.Original, at, nil)
			history := r.indexed[ev.Original]
			r.admissionMu.Lock()
			r.noteDecodeLossLocked(pkt, history)
			r.admissionMu.Unlock()
			notice := <-r.losses
			connection := states[0].Connection.Load()
			if removal == "deny" {
				d := e.rememberDeniedTCP(packetKey(pkt), packetKey(pkt))
				if d == nil {
					t.Fatal("fixture did not create a denial tombstone")
				}
				e.retireDeniedTCP(d, false)
			} else {
				e.sweepFlows(at.Add(time.Hour))
			}
			if len(e.transportCoverage) != 0 || len(e.flows) != 0 {
				t.Fatal("retirement retained directional flow coverage")
			}
			// Model a packet that obtained a state before retirement and
			// arrives at binding afterwards. Neither it nor a late loss
			// notice may put the forgotten state back in the coverage map.
			e.flowMu.Lock()
			r.admissionMu.Lock()
			for _, st := range states {
				e.bindDecodeCoverageLocked(st, history)
			}
			r.admissionMu.Unlock()
			e.flowMu.Unlock()
			if len(e.transportCoverage) != 0 {
				t.Fatal("late packet binding resurrected retired coverage")
			}
			e.consumeDecodeLoss(notice, connection)
			if len(e.transportCoverage) != 0 || len(e.flows) != 0 {
				t.Fatal("late loss notice resurrected a retired flow")
			}
		})
	}
}

func TestTransportCoverageStaleBinding(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	r.authority.check(context.Background())
	pkt := transportWire(ev.Original, time.Now(), nil)
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	old := e.tupleStateLocked(ev.Original)
	e.flowMu.Lock()
	e.dropFlowLocked(old.Key)
	e.flowMu.Unlock()
	e.endFlowStream(old, nil)
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	current := e.tupleStateLocked(ev.Original)
	marker := e.transportCoverage[current]
	if current == nil || current == old || marker == nil {
		t.Fatal("fixture did not replace the flow at the same key")
	}
	e.flowMu.Lock()
	r.admissionMu.Lock()
	e.bindDecodeCoverageLocked(old, r.indexed[ev.Original])
	r.admissionMu.Unlock()
	e.flowMu.Unlock()
	if len(e.transportCoverage) != 1 || e.transportCoverage[current] != marker {
		t.Fatal("stale packet binding attached a replaced state")
	}
	r.admissionMu.Lock()
	r.noteDecodeLossLocked(pkt, r.indexed[ev.Original])
	r.admissionMu.Unlock()
	e.consumeDecodeLoss(<-r.losses, current.Connection.Load())
	if len(e.transportCoverage) != 1 || e.transportCoverage[old] != nil {
		t.Fatal("loss consumption resurrected the replaced state")
	}
}

type coverageEndDecoder struct {
	*modbus.Decoder
	ended map[string]int
}

func (d *coverageEndDecoder) StreamEnded(session string, _ dpi.StreamDir) {
	d.ended[session]++
}

func TestTransportCoverageStopsBothDirections(t *testing.T) {
	for _, mode := range []string{"nat", "wire"} {
		for _, lossDirection := range []string{"original", "reply"} {
			t.Run(mode+"/"+lossDirection, func(t *testing.T) {
				ev := natEvidence()
				reader := &transportCTFake{evidence: ev}
				if mode == "wire" {
					ev.Reply = flow.TupleKey(ev.Original, flow.DirForward).Reversed().Tuple()
					reader.err = conntrack.ErrNotFound
				}
				e, r, _ := newTransportTest(t, reader)
				decoder := &coverageEndDecoder{Decoder: modbus.NewDecoder(), ended: make(map[string]int)}
				e.dpiMgr = dpi.NewManager(decoder)
				r.authority.check(context.Background())
				at := time.Now()
				request := transportWire(ev.Original, at, modbusADU(1, 3, 10, 2))
				reply := transportWire(ev.Reply, at.Add(time.Millisecond), modbusReadReply(1))
				r.admit(e, request)
				processTransportAdmission(t, e, r)
				r.admit(e, reply)
				processTransportAdmission(t, e, r)
				if len(transportModbusEvents(e)) != 2 || len(decoder.ended) != 0 {
					t.Fatal("fixture did not establish both directional streams")
				}
				lost := request
				if lossDirection == "reply" {
					lost = reply
				}
				lost.Timestamp = at.Add(2 * time.Millisecond)
				r.admissionMu.Lock()
				r.noteDecodeLossLocked(lost, r.indexed[packetKey(lost).Tuple()])
				r.admissionMu.Unlock()
				notice := <-r.losses
				e.consumeDecodeLoss(notice, r.resolve(context.Background(), notice.packet, false))
				// Assert immediate stream teardown, before a later packet
				// could lazily discover the stop on its own direction.
				for _, tuple := range []conntrack.Tuple{ev.Original, ev.Reply} {
					st := e.tupleStateLocked(tuple)
					if st == nil || !e.decodingStopped(st) {
						t.Fatal("loss did not stop both directional states")
					}
					if decoder.ended[st.Key.Hash()] != 1 {
						t.Fatalf("loss did not discard directional stream %s: %v", st.Key.Hash(), decoder.ended)
					}
				}
				request.Timestamp, request.Payload = at.Add(3*time.Millisecond), modbusADU(2, 3, 10, 2)
				reply.Timestamp, reply.Payload = at.Add(4*time.Millisecond), modbusReadReply(2)
				r.admit(e, request)
				processTransportAdmission(t, e, r)
				r.admit(e, reply)
				processTransportAdmission(t, e, r)
				if len(transportModbusEvents(e)) != 2 || coverageLossCount(e) != 1 {
					t.Fatal("directional decoding continued after loss")
				}
			})
		}
	}
}
