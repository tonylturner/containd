// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

func cappedFlowEngine(t *testing.T, slots int) *Engine {
	t.Helper()
	e, err := New(Config{Limits: limits.Limits{MaxFlows: slots}, DPIEnabled: true, ResetInjector: &session.Fake{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func TestFlowSlotsReservePeerAndReleaseLastDirection(t *testing.T) {
	for _, proto := range []uint8{6, 17, 1} {
		t.Run(fmt.Sprint(proto), func(t *testing.T) {
			e := cappedFlowEngine(t, 4)
			now := time.Now()
			p := segment(false, 100, capture.TCPFlagSYN, nil)
			p.Proto = proto
			first := e.trackFlow(p, now)
			if got := e.LimitOccupancy(); first == nil || got.Entries != 2 || got.Limit != 4 || got.HighWater != 2 {
				t.Fatalf("first admission: %+v", got)
			}
			q := segment(true, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil)
			q.Proto = proto
			peer := e.trackFlow(q, now)
			if peer == nil || e.LimitOccupancy().Entries != 2 {
				t.Fatal("reserved peer was refused or charged twice")
			}
			e.flowMu.Lock()
			e.dropFlowLocked(first.Key)
			e.flowMu.Unlock()
			if e.LimitOccupancy().Entries != 2 {
				t.Fatal("refunded a live peer's reservation")
			}
			e.flowMu.Lock()
			e.dropFlowLocked(peer.Key)
			e.flowMu.Unlock()
			if e.LimitOccupancy().Entries != 0 {
				t.Fatal("leaked the final reservation")
			}
		})
	}
}

func TestFlowSlotsHeadroomRefusalAndAccounting(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor", "passive"} {
		t.Run(mode, func(t *testing.T) {
			e := cappedFlowEngine(t, 8)
			e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{{
				ID: "inspect", Action: rules.ActionAllow,
				ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"},
			}}})
			packet := func(port uint16, inline bool) capture.Packet {
				p := connSegment(false, port, 502, 100, capture.TCPFlagSYN, nil)
				if inline {
					p.Token = capture.NewToken(1, uint32(port))
					p.Mark |= markabi.EnforceScopeMark
				}
				return p
			}
			// Observation may occupy only six of the eight slots.
			for port := uint16(41000); port < 41003; port++ {
				e.HandlePacket(packet(port, false))
			}
			if e.LimitOccupancy().Entries != 6 {
				t.Fatal("observation slots not reserved in pairs")
			}
			if d := e.HandlePacket(packet(41003, false)); d.Action != capture.Accept || e.LimitOccupancy().Entries != 6 {
				t.Fatalf("observation overflow: %+v", d)
			}
			// Enforcement can use the remaining pair.
			if d := e.HandlePacket(packet(41004, true)); d.Action == capture.Drop || e.LimitOccupancy().Entries != 8 {
				t.Fatalf("enforce headroom: %+v", d)
			}
			if mode == "monitor" {
				e.LoadRules(rules.Snapshot{Default: rules.ActionAllow})
			}
			p := packet(41005, mode != "passive")
			if mode == "monitor" {
				p.Mark &^= markabi.EnforceScopeMark
			}
			before := e.verdictCache.Len()
			for range 3 {
				d := e.HandlePacket(p)
				want := capture.Accept
				if mode == "enforce" {
					want = capture.Drop
					if d.Reason != "state_limit" {
						t.Fatalf("reason: %+v", d)
					}
				} else if mode == "monitor" {
					want = capture.Repeat
				}
				if d.Action != want || e.LimitOccupancy().Entries != 8 {
					t.Fatalf("refusal: %+v", d)
				}
			}
			if len(e.deniedTCP) != 0 || before != e.verdictCache.Len() {
				t.Fatal("flow refusal created a denial marker")
			}
			row := e.ledger.Status(limits.TableFlows, e.LimitOccupancy())
			var enforce, monitor uint64
			for _, h := range row.Hits {
				if h.Mode == limits.ModeEnforce {
					enforce += h.Total
				} else if h.Mode == limits.ModeMonitor {
					monitor += h.Total
				}
			}
			wantEnforce, wantMonitor := uint64(0), uint64(4)
			if mode == "enforce" {
				wantEnforce, wantMonitor = 3, 1
			}
			if enforce != wantEnforce || monitor != wantMonitor {
				t.Fatalf("refusal counts %+v", row.Hits)
			}
		})
	}
}

func TestFlowSlotsSweepBeforeRefusal(t *testing.T) {
	e := cappedFlowEngine(t, 4)
	now := time.Now()
	p := segment(false, 100, capture.TCPFlagSYN, nil)
	if e.trackFlow(p, now) == nil {
		t.Fatal("initial admission")
	}
	p.SrcPort++
	if e.trackFlow(p, now.Add(31*time.Second)) == nil {
		t.Fatal("refused before sweeping the expired unestablished owner")
	}
	if e.LimitOccupancy().Entries != 2 || len(e.flows) != 1 {
		t.Fatal("expired reservation retained")
	}
}

func TestFlowSlotsNATAssociationReturnsDuplicateReservation(t *testing.T) {
	e := cappedFlowEngine(t, 8)
	now := time.Now()
	p := segment(false, 100, capture.TCPFlagSYN, nil)
	q := segment(true, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil)
	q.DstPort++ // reply after translation, not the raw reverse tuple
	a, b := e.trackFlow(p, now), e.trackFlow(q, now)
	if e.LimitOccupancy().Entries != 4 {
		t.Fatal("independent wire histories did not reserve separately")
	}
	c := &flow.Connection{Key: "nat", Evidence: &conntrack.Evidence{
		Original: a.Key.Tuple(), Reply: b.Key.Tuple(),
	}}
	e.bindTransport(a, c)
	if e.LimitOccupancy().Entries != 2 {
		t.Fatal("association leaked the duplicate reservation")
	}
	e.flowMu.Lock()
	e.dropFlowLocked(a.Key)
	e.dropFlowLocked(b.Key)
	e.flowMu.Unlock()
	if e.LimitOccupancy().Entries != 0 {
		t.Fatal("association double-refunded or leaked")
	}
}

func TestFlowSlotsNATPeerUsesReservedCapacity(t *testing.T) {
	e := cappedFlowEngine(t, 4) // observation may use only one pair
	now := time.Now()
	p := segment(false, 100, capture.TCPFlagSYN, nil)
	q := segment(true, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil)
	q.DstPort++
	c := &flow.Connection{Key: "nat", Evidence: &conntrack.Evidence{
		Original: packetKey(p).Tuple(), Reply: packetKey(q).Tuple(),
	}}
	a := e.trackTransportFlow(p, now, c)
	e.bindTransport(a, c)
	b := e.trackTransportFlow(q, now, c)
	if b == nil || e.LimitOccupancy().Entries != 2 {
		t.Fatal("translated peer did not use its reserved slot")
	}
}

func TestFlowSlotsExpiryDistinguishesEstablished(t *testing.T) {
	for _, proto := range []uint8{6, 17, 1} {
		for _, established := range []bool{false, true} {
			t.Run(fmt.Sprint(proto, "/", established), func(t *testing.T) {
				e := cappedFlowEngine(t, 8)
				now := time.Now()
				p := segment(false, 100, capture.TCPFlagSYN, nil)
				p.Proto = proto
				e.trackFlow(p, now)
				if established {
					q := segment(true, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil)
					q.Proto = proto
					q.TCP.Ack = 100
					e.trackFlow(q, now)
					p.TCP.Flags = capture.TCPFlagACK
					p.TCP.Seq, p.TCP.Ack = 100, 500
					e.trackFlow(p, now)
				}
				e.sweepFlows(now.Add(31 * time.Second))
				want := int64(0)
				if established {
					want = 2
				}
				if got := e.LimitOccupancy().Entries; got != want {
					t.Fatalf("slots after 31 s = %d, want %d", got, want)
				}
				e.sweepFlows(now.Add(5*time.Minute + time.Second))
				if e.LimitOccupancy().Entries != 0 {
					t.Fatal("established reservation did not expire")
				}
			})
		}
	}
}

func TestFlowSlotsCloseReturnsReservations(t *testing.T) {
	e := cappedFlowEngine(t, 4)
	e.trackFlow(segment(false, 100, capture.TCPFlagSYN, nil), time.Now())
	e.Close()
	e.Close()
	if got := e.LimitOccupancy(); got.Entries != 0 || got.HighWater != 2 {
		t.Fatalf("close retained or double-refunded slots: %+v", got)
	}
}

func TestFlowSlotsTranslatedDatagramReplyEstablishesConnection(t *testing.T) {
	e := cappedFlowEngine(t, 4)
	now := time.Now()
	p := connSegment(false, 41000, 40001, 0, 0, nil)
	q := connSegment(true, 41001, 40001, 0, 0, nil)
	p.Proto, q.Proto = 17, 17
	c := &flow.Connection{Key: "datagram-nat", Evidence: &conntrack.Evidence{
		Original: packetKey(p).Tuple(), Reply: packetKey(q).Tuple(),
	}}
	a := e.trackTransportFlow(p, now, c)
	e.bindTransport(a, c)
	b := e.trackTransportFlow(q, now, c)
	e.bindTransport(b, c)
	e.sweepFlows(now.Add(31 * time.Second))
	if e.LimitOccupancy().Entries != 2 {
		t.Fatal("translated datagram reply did not establish the reservation")
	}
}
