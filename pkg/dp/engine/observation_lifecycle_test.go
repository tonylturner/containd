// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/identify"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func newObservationEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{Capture: capture.Config{Interfaces: []string{"eth0"}}, DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e.observation != nil {
			e.observation.observer.Drain()
			e.observation.syncMetrics()
		}
	})
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{{ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "learn"}, Action: rules.ActionAllow}}})
	return e
}

func TestObservationAdoption(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "bound"}[bound], func(t *testing.T) {
			e := newObservationEngine(t)
			ev := natEvidence()
			ev.Original.Destination = netip.AddrPortFrom(ev.Original.Destination.Addr(), 1502)
			ev.Reply.Source = netip.AddrPortFrom(ev.Reply.Source.Addr(), 1502)
			trace := observationTrace(1502, false)
			// Separate unresolved O/R histories, as seen before NAT authority arrives.
			for i := range trace {
				tuple := ev.Original
				if i%2 == 1 {
					tuple = ev.Reply
				}
				p := transportWire(tuple, trace[i].Timestamp, trace[i].Payload)
				p.TCP = trace[i].TCP
				trace[i] = p
			}
			e.HandlePacket(trace[0])
			e.HandlePacket(trace[1])
			original := e.tupleStateLocked(ev.Original)
			reply := e.tupleStateLocked(ev.Reply)
			from, to := reply.Connection.Load().Key, original.Connection.Load().Key
			if from == to {
				t.Fatal("fixture did not create independent pending identities")
			}
			var frozen string
			if bound {
				// Bind one pending NAT history with its exact peer before authority is
				// available, then merge it into the other pending incarnation.
				peer := trace[0]
				peer.SrcIP, peer.DstIP = trace[1].DstIP, trace[1].SrcIP
				peer.SrcPort, peer.DstPort = trace[1].DstPort, trace[1].SrcPort
				peer.TCP.Seq = 100
				e.HandlePacket(peer)
				request := peer
				request.TCP = trace[2].TCP
				request.Payload = trace[2].Payload
				e.HandlePacket(request)
				e.HandlePacket(trace[3])
				status, ok := e.observation.observer.Lookup(identify.Key(from))
				if !ok || !status.Observed {
					t.Fatal("pre-adoption binding missing")
				}
				frozen = status.Session
			}
			e.bindTransport(reply, &flow.Connection{Key: "resolved-new", ID: "verified", Status: "resolved", Evidence: &ev})
			if reply.Connection.Load().Key != to || original.Connection.Load().Key != to {
				t.Fatal("adoption did not preserve original incarnation")
			}
			if _, ok := e.observation.observer.Lookup(identify.Key(from)); ok {
				t.Fatal("old observer key survived adoption")
			}
			if bound {
				status, _ := e.observation.observer.Lookup(identify.Key(to))
				if !status.Observed || status.Session != frozen {
					t.Fatal("binding/session lost on adoption")
				}
			} else {
				e.HandlePacket(trace[2])
				e.HandlePacket(trace[3])
			}
			e.flowMu.Lock()
			pending := e.observationPending
			e.observationPending = nil
			e.flowMu.Unlock()
			e.recordObservations(pending)
			ids := 0
			for _, event := range e.Events().List(0) {
				if event.Proto == "identify" {
					ids++
				}
			}
			if ids != 1 {
				t.Fatalf("identifications=%d, events=%+v", ids, e.Events().List(0))
			}
		})
	}
}

func TestObservationLifecycle(t *testing.T) {
	for _, port := range []uint16{1502, 2404} {
		t.Run(map[uint16]string{1502: "alternate", 2404: "2404"}[port], func(t *testing.T) {
			e := newObservationEngine(t)
			trace := observationTrace(port, false)
			now := trace[0].Timestamp
			e.observation.now = func() time.Time { return now }
			e.HandlePacket(trace[0])
			st := e.tupleStateLocked(packetKey(trace[0]).Tuple())
			key := identify.Key(st.Connection.Load().Key)
			now = now.Add(6 * time.Second)
			e.sweepFlows(now)
			if e.observation.observer.Counters().Entries != 0 {
				t.Fatal("idle pending evidence not swept")
			}
			next := trace[0]
			next.TCP.Seq++
			e.HandlePacket(next)
			fresh := e.tupleStateLocked(packetKey(next).Tuple())
			if fresh.Connection.Load().Key == string(key) {
				t.Fatal("new ISN reused incarnation")
			}
			if _, ok := e.observation.observer.Lookup(key); ok {
				t.Fatal("retired marker leaked")
			}
			e.sweepFlows(now.Add(6 * time.Minute))
			if got := e.observation.observer.Counters(); got.Markers != 0 || got.Bindings != 0 || got.ChargedBytes != 0 {
				t.Fatalf("expiry leaked: %+v", got)
			}
		})
	}
}

func TestObservationNFQueueDisabled(t *testing.T) {
	for _, cfg := range []Config{{NFQueueGroup: 3, Capture: capture.Config{Interfaces: []string{"eth0"}}}, {Capture: capture.Config{Mode: "nfqueue", Interfaces: []string{"eth0"}}}, {}} {
		e, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if e.observation != nil {
			t.Fatal("observer constructed outside passive capture")
		}
	}
}

func TestObservationReconfigure(t *testing.T) {
	e := newObservationEngine(t)
	e.capture = idleCapture{}
	// The real transport worker can still be resolving an observation while
	// Reconfigure stops it. Its reader honors cancellation, not a test sleep.
	fake := &transportCTFake{evidence: natEvidence(), started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	oldTransport, err := newTransportResolver(&transportZoneFake{}, fake)
	if err != nil {
		t.Fatal(err)
	}
	e.transport = oldTransport
	old := e.observation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	e.HandlePacket(observationTrace(1502, false)[0])
	oldTransport.admit(e, transportWire(natEvidence().Original, time.Now(), nil))
	select {
	case <-fake.started:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not enter lookup")
	}
	fresh := newObservationEngine(t)
	fresh.capture = idleCapture{}
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	if old.observer.Counters().Markers != 0 {
		t.Fatal("reconfigure retained old markers")
	}
	if old.observer.Open("stale", identify.Meta{Transport: 6}) {
		t.Fatal("disposed observer reopened")
	}
	if e.observation != fresh.observation {
		t.Fatal("replacement was not installed")
	}
	select {
	case <-fake.closed:
	default:
		t.Fatal("old reader still running")
	}
	for _, p := range observationTrace(1502, false) {
		e.HandlePacket(p)
	}
	if e.observation.observer.Counters().Outcomes[0][0] != 1 {
		t.Fatal("fresh observer did not decode")
	}
}

func TestObservationGenerationAndContradiction(t *testing.T) {
	for _, port := range []uint16{1502, 2404} {
		t.Run(map[uint16]string{1502: "alternate", 2404: "2404"}[port], func(t *testing.T) {
			e := newObservationEngine(t)
			trace := observationTrace(port, false)
			evidence := conntrack.Evidence{ID: 1, Start: 1, TimeoutSeconds: 120, Original: packetKey(trace[0]).Tuple(), Reply: packetKey(trace[1]).Tuple()}
			e.handleTransportPacket(trace[0], &flow.Connection{Key: "generation-1", ID: "generation-1", Status: "resolved", Evidence: &evidence}, nil)
			nextEvidence := evidence
			nextEvidence.ID++
			nextEvidence.Start++
			next := trace[0]
			next.TCP.Flags = capture.TCPFlagACK
			e.handleTransportPacket(next, &flow.Connection{Key: "generation-2", ID: "generation-2", Status: "resolved", Evidence: &nextEvidence}, nil)
			if _, ok := e.observation.observer.Lookup("generation-1"); ok {
				t.Fatal("old CT generation survived")
			}
			if _, ok := e.observation.observer.Lookup("generation-2"); !ok {
				t.Fatal("new CT generation was not opened")
			}
			// An unanchored direction whose later SYN-ACK contradicts its orientation
			// also owns a fresh observer key, independently of the generic TCP stripe.
			mid := trace[2]
			mid.SrcPort++
			e.HandlePacket(mid)
			old := identify.Key(e.tupleStateLocked(packetKey(mid).Tuple()).Connection.Load().Key)
			contradiction := mid
			contradiction.Payload = nil
			contradiction.TCP.Flags = capture.TCPFlagSYN | capture.TCPFlagACK
			e.HandlePacket(contradiction)
			current := e.tupleStateLocked(packetKey(mid).Tuple()).Connection.Load().Key
			if string(old) == current {
				t.Fatal("contradicted handshake reused key")
			}
			if _, ok := e.observation.observer.Lookup(old); ok {
				t.Fatal("contradicted marker leaked")
			}
		})
	}
}
