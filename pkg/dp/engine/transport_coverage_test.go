// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func coverageLossCount(e *Engine) int {
	n := 0
	for _, ev := range e.Events().List(0) {
		if ev.Kind == eventfields.KindCoverageLoss {
			n++
		}
	}
	return n
}

func TestTransportCoverageOverflow(t *testing.T) {
	for _, capacity := range []string{"queue", "bytes"} {
		t.Run(capacity, func(t *testing.T) {
			evidence := natEvidence()
			e, r, _ := newTransportTest(t, &transportCTFake{evidence: evidence})
			r.authority.check(context.Background())
			at := time.Now()
			pkt := transportWire(evidence.Original, at, nil)
			pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
			r.admit(e, pkt)
			processTransportAdmission(t, e, r)
			pkt.Timestamp, pkt.Payload = at.Add(time.Millisecond), modbusADU(1, 3, 10, 2)
			pkt.TCP.Flags, pkt.TCP.Seq = capture.TCPFlagACK, 101
			r.admit(e, pkt)
			processTransportAdmission(t, e, r)
			if len(transportModbusEvents(e)) != 1 {
				t.Fatal("fixture did not decode the initial frame")
			}
			id := transportModbusEvents(e)[0].TransportConnectionID
			before := testutil.ToFloat64(metrics.DPICoverageLosses)
			// Both frames are admitted before the loss. Worker timestamp order,
			// not admission order, must preserve only the earlier one.
			pkt.Timestamp, pkt.Payload, pkt.TCP.Seq = at.Add(2*time.Millisecond), modbusADU(2, 3, 10, 2), 113
			r.admit(e, pkt)
			pkt.Timestamp, pkt.Payload, pkt.TCP.Seq = at.Add(3*time.Millisecond), modbusADU(3, 3, 10, 2), 125
			if capacity == "queue" {
				r.admit(e, pkt) // Equal-time bytes must lose to the notice.
				filler := pkt
				filler.Timestamp, filler.Payload = at.Add(2*time.Millisecond), nil
				for r.count.Load() < transportQueueLimit {
					r.admit(e, filler)
				}
			} else {
				pkt.Payload = make([]byte, transportByteLimit+1)
			}
			for range 2 {
				if d := r.admit(e, pkt); d.Action != capture.Accept || d.Reason != "" || len(d.Resolved) != 0 {
					t.Fatalf("overflow changed forwarding: %+v", d)
				}
			}
			if coverageLossCount(e) != 0 || len(transportModbusEvents(e)) != 1 {
				t.Fatal("capture admission decoded or consumed the loss synchronously")
			}
			cancel, done := runTransportTest(t, e, r)
			waitTransport(t, func() bool { return r.count.Load() == 0 && coverageLossCount(e) == 1 })
			if got := len(transportModbusEvents(e)); got != 2 {
				t.Fatalf("timestamp ordering decoded %d frames, want two before loss", got)
			}
			// A retransmission fills the actual hole, but may not restart DPI.
			pkt.Payload = modbusADU(3, 3, 10, 2)
			pkt.Timestamp = at.Add(4 * time.Millisecond)
			r.admit(e, pkt)
			pkt.Payload, pkt.TCP.Seq = modbusADU(4, 3, 10, 2), 137
			pkt.Timestamp = at.Add(5 * time.Millisecond)
			r.admit(e, pkt)
			reply := transportWire(evidence.Reply, at.Add(6*time.Millisecond), modbusReadReply(1))
			r.admit(e, reply)
			waitTransport(t, func() bool { return r.count.Load() == 0 })
			if got := len(transportModbusEvents(e)); got != 2 {
				t.Fatalf("decoder crossed the loss, events=%d", got)
			}
			pkt.Timestamp, pkt.Payload = at.Add(7*time.Millisecond), nil
			pkt.TCP.Flags, pkt.TCP.Seq = capture.TCPFlagSYN, 1000
			r.admit(e, pkt)
			pkt.Timestamp, pkt.Payload = at.Add(8*time.Millisecond), modbusADU(5, 3, 10, 2)
			pkt.TCP.Flags, pkt.TCP.Seq = capture.TCPFlagACK, 1001
			r.admit(e, pkt)
			waitTransport(t, func() bool { return r.count.Load() == 0 })
			cancel()
			<-done
			if got := len(transportModbusEvents(e)); got != 3 {
				t.Fatalf("new ISN did not recover decoding: %d", got)
			}
			if coverageLossCount(e) != 1 || testutil.ToFloat64(metrics.DPICoverageLosses)-before != 1 {
				t.Fatal("coverage loss was not counted exactly once")
			}
			for _, ev := range e.Events().List(0) {
				if ev.Kind == eventfields.KindCoverageLoss &&
					(ev.TransportConnectionID != id || !ev.Timestamp.Equal(at.Add(3*time.Millisecond))) {
					t.Fatalf("loss attribution: %+v", ev)
				}
			}
		})
	}
}

func TestTransportCoverageNoticeCapacity(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	r.authority.check(context.Background())
	pkt := transportWire(natEvidence().Original, time.Now(), modbusADU(1, 3, 10, 2))
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	// Saturate only notice storage: packet accounting is independent of it.
	for range cap(r.losses) {
		r.losses <- transportPacket{}
	}
	r.admissionMu.Lock()
	history := r.indexed[natEvidence().Original]
	r.noteDecodeLossLocked(pkt, history)
	r.admissionMu.Unlock()
	notices := r.decodeLossFallback(e, nil)
	if len(notices) != 1 || len(r.losses) != cap(r.losses) || r.count.Load() != 0 {
		t.Fatal("full notice storage lost its bounded fallback marker")
	}
	e.consumeDecodeLoss(notices[0], r.resolve(context.Background(), notices[0].packet, false))
	pkt.Payload = modbusADU(2, 3, 10, 2)
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	if len(transportModbusEvents(e)) != 1 || coverageLossCount(e) != 1 {
		t.Fatal("notice-capacity fallback decoded across the hole")
	}
}

func TestTransportCoverageObservationAndGeneration(t *testing.T) {
	ev := natEvidence()
	ev.Original.Destination = netip.AddrPortFrom(ev.Original.Destination.Addr(), 1502)
	ev.Reply.Source = netip.AddrPortFrom(ev.Reply.Source.Addr(), 1502)
	reader := &transportCTFake{evidence: ev}
	e, r, _ := newTransportTest(t, reader)
	var err error
	e.observation, err = newLiveObserver(Config{DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	r.authority.check(context.Background())
	at := time.Now()
	pkt := transportWire(ev.Original, at, nil)
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	reply := transportWire(ev.Reply, at.Add(time.Millisecond), nil)
	reply.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN | capture.TCPFlagACK, Seq: 200}
	r.admit(e, reply)
	processTransportAdmission(t, e, r)
	pkt.Timestamp, pkt.Payload = at.Add(2*time.Millisecond), modbusADU(1, 3, 10, 2)
	pkt.TCP.Flags, pkt.TCP.Seq = capture.TCPFlagACK, 101
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	reply.Timestamp, reply.Payload = at.Add(3*time.Millisecond), modbusReadReply(1)
	reply.TCP.Flags, reply.TCP.Seq = capture.TCPFlagACK, 201
	r.admit(e, reply)
	processTransportAdmission(t, e, r)
	if len(transportModbusEvents(e)) != 2 {
		t.Fatal("fixture did not establish passive alternate-port decoding")
	}
	r.admissionMu.Lock()
	r.noteDecodeLossLocked(pkt, r.indexed[ev.Original])
	r.admissionMu.Unlock()
	notice := <-r.losses
	e.consumeDecodeLoss(notice, r.resolve(context.Background(), notice.packet, false))
	pkt.Timestamp, pkt.Payload, pkt.TCP.Seq = at.Add(4*time.Millisecond), modbusADU(2, 3, 10, 2), 113
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	reply.Timestamp, reply.Payload, reply.TCP.Seq = at.Add(5*time.Millisecond), modbusReadReply(2), 214
	r.admit(e, reply)
	processTransportAdmission(t, e, r)
	if len(transportModbusEvents(e)) != 2 || e.observation.observer.Counters().Bindings != 0 {
		t.Fatal("passive binding continued after loss")
	}
	// No new SYN: a verified CT generation is the other existing boundary.
	reader.mu.Lock()
	reader.evidence.ID++
	reader.evidence.Start++
	reader.mu.Unlock()
	for _, alias := range r.aliases {
		alias.expires = time.Time{}
	}
	pkt.Timestamp, pkt.Payload = at.Add(6*time.Millisecond), nil
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	e.flowMu.Lock()
	state := e.tupleStateLocked(ev.Original)
	e.flowMu.Unlock()
	if e.decodingStopped(state) {
		t.Fatal("verified new CT generation inherited the predecessor's loss")
	}
}

func TestTransportCoverageUnverifiedRecovery(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{err: conntrack.ErrNotFound})
	r.authority.check(context.Background())
	at := time.Now()
	pkt := transportWire(natEvidence().Original, at, nil)
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	pkt.Payload, pkt.TCP.Flags, pkt.TCP.Seq = modbusADU(1, 3, 10, 2), capture.TCPFlagACK, 101
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	// A reverse-direction loss before that direction has any flow state
	// still terminates the existing, wire-associated connection.
	reply := transportWire(packetKey(pkt).Reversed().Tuple(), at.Add(time.Millisecond), modbusReadReply(1))
	r.count.Store(transportQueueLimit)
	r.admit(e, reply)
	r.count.Store(0)
	notice := <-r.losses
	e.consumeDecodeLoss(notice, r.resolve(context.Background(), notice.packet, false))
	pkt.Timestamp, pkt.Payload, pkt.TCP.Seq = at.Add(2*time.Millisecond), modbusADU(2, 3, 10, 2), 113
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	if len(transportModbusEvents(e)) != 1 {
		t.Fatal("unverified reverse loss did not stop the connection")
	}
	pkt.Timestamp, pkt.Payload = at.Add(3*time.Millisecond), nil
	pkt.TCP.Flags, pkt.TCP.Seq = capture.TCPFlagSYN, 1000
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	pkt.Timestamp, pkt.Payload = at.Add(4*time.Millisecond), modbusADU(3, 3, 10, 2)
	pkt.TCP.Flags, pkt.TCP.Seq = capture.TCPFlagACK, 1001
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	if len(transportModbusEvents(e)) != 2 || coverageLossCount(e) != 1 {
		t.Fatal("existing raw new-ISN boundary did not recover without conntrack")
	}
}

func TestTransportCoverageUnindexedBarrier(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	r.authority.check(context.Background())
	for i := range transportAliasLimit {
		r.indexed[round3FloodTuple(i)] = &transportAdmission{connection: &flow.Connection{Key: "occupied"}}
	}
	pkt := transportWire(natEvidence().Original, time.Now(), modbusADU(1, 3, 10, 2))
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	if len(transportModbusEvents(e)) != 1 {
		t.Fatal("index exhaustion alone stopped decoding without a packet loss")
	}
	lost := transportWire(round3FloodTuple(transportAliasLimit+1), time.Now(), nil)
	r.count.Store(transportQueueLimit)
	r.admit(e, lost)
	r.count.Store(0)
	pkt.Timestamp, pkt.Payload = time.Now(), modbusADU(2, 3, 10, 2)
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	if len(transportModbusEvents(e)) != 1 || coverageLossCount(e) != 1 {
		t.Fatal("unindexed transport loss did not conservatively stop an existing stream")
	}
	pkt.Timestamp, pkt.Payload = time.Now(), nil
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 1000}
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	pkt.Timestamp, pkt.Payload = time.Now(), modbusADU(3, 3, 10, 2)
	pkt.TCP.Flags, pkt.TCP.Seq = capture.TCPFlagACK, 1001
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	if len(transportModbusEvents(e)) != 2 {
		t.Fatal("unindexed barrier poisoned a later incarnation")
	}
}

func TestTransportCoverageLossFollowsWorkerGeneration(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(map[bool]string{false: "notice", true: "capacity"}[full], func(t *testing.T) {
			reader := &transportCTFake{evidence: natEvidence()}
			e, r, _ := newTransportTest(t, reader)
			r.authority.check(context.Background())
			pkt := transportWire(natEvidence().Original, time.Now(), modbusADU(1, 3, 10, 2))
			r.admit(e, pkt)
			processTransportAdmission(t, e, r)
			oldID := transportModbusEvents(e)[0].TransportConnectionID
			reader.mu.Lock()
			reader.evidence.ID++
			reader.evidence.Start++
			reader.mu.Unlock()
			for _, alias := range r.aliases {
				alias.expires = time.Time{}
			}
			pkt.Timestamp, pkt.Payload = time.Now(), modbusADU(2, 3, 10, 2)
			r.admit(e, pkt)
			dropped := pkt
			dropped.Timestamp, dropped.Payload = time.Now(), make([]byte, transportByteLimit+1)
			if full {
				for range cap(r.losses) {
					r.losses <- transportPacket{}
				}
			}
			r.admit(e, dropped)
			processTransportAdmission(t, e, r)
			if len(transportModbusEvents(e)) != 2 {
				t.Fatal("loss admission stopped bytes ordered before it in the new generation")
			}
			newID := transportModbusEvents(e)[0].TransportConnectionID
			var notice transportPacket
			if full {
				notices := r.decodeLossFallback(e, nil)
				if len(notices) != 1 {
					t.Fatalf("generation retirement discarded the fallback: %d notices", len(notices))
				}
				notice = notices[0]
			} else {
				notice = <-r.losses
			}
			e.consumeDecodeLoss(notice, r.resolve(context.Background(), notice.packet, false))
			pkt.Timestamp, pkt.Payload = time.Now(), modbusADU(3, 3, 10, 2)
			r.admit(e, pkt)
			processTransportAdmission(t, e, r)
			if oldID == newID || len(transportModbusEvents(e)) != 2 || coverageLossCount(e) != 1 {
				t.Fatal("loss was applied to the admission-time predecessor instead of the worker generation")
			}
			for _, ev := range e.Events().List(0) {
				if ev.Kind == eventfields.KindCoverageLoss && ev.TransportConnectionID != newID {
					t.Fatal("coverage event attributed the loss to the predecessor")
				}
			}
		})
	}
}

func TestTransportCoverageIECTable(t *testing.T) {
	ev := natEvidence()
	ev.Original.Destination = netip.AddrPortFrom(ev.Original.Destination.Addr(), 2404)
	ev.Reply = flow.TupleKey(ev.Original, flow.DirForward).Reversed().Tuple()
	reader := &transportCTFake{evidence: ev}
	e, r, _ := newTransportTest(t, reader)
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{{
		ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"}, Action: rules.ActionAllow,
	}}})
	r.authority.check(context.Background())
	trace := observationTrace(2404, true)
	for i := range trace {
		tuple := ev.Original
		if i%2 != 0 {
			tuple = ev.Reply
		}
		pkt := transportWire(tuple, trace[i].Timestamp, trace[i].Payload)
		pkt.TCP = trace[i].TCP
		trace[i] = pkt
		r.admit(e, pkt)
		processTransportAdmission(t, e, r)
	}
	decoded := func() int {
		n := 0
		for _, event := range e.Events().List(0) {
			if event.Proto == "iec104" && (event.Kind == "request" || event.Kind == "response" || event.Kind == "apci") {
				n++
			}
		}
		return n
	}
	before := decoded()
	if before == 0 {
		t.Fatal("fixture did not decode the table-owned IEC session")
	}
	pkt := trace[4]
	pkt.Timestamp = trace[5].Timestamp.Add(time.Millisecond)
	pkt.TCP.Seq += uint32(len(pkt.Payload))
	dropped := pkt
	dropped.Payload = make([]byte, transportByteLimit+1)
	r.admit(e, dropped)
	notice := <-r.losses
	e.consumeDecodeLoss(notice, r.resolve(context.Background(), notice.packet, false))
	if decision := e.HandlePacket(pkt); decision.Action != capture.Accept {
		t.Fatalf("coverage loss changed the table's learn forwarding: %+v", decision)
	}
	if decoded() != before || coverageLossCount(e) != 1 {
		t.Fatal("table-owned IEC parser continued after loss")
	}
	// Close through the table's existing in-window RST, then open a new
	// table incarnation; no new recovery criterion is introduced.
	e.iec.mu.Lock()
	src, _ := addrPort(pkt.SrcIP, pkt.SrcPort)
	dst, _ := addrPort(pkt.DstIP, pkt.DstPort)
	session, _ := e.iec.lookupLocked(src, dst)
	pkt.TCP.Seq = forwardedSeq(session.dirs[iecDirClient])
	e.iec.mu.Unlock()
	pkt.Payload, pkt.TCP.Flags = nil, capture.TCPFlagRST
	e.HandlePacket(pkt)
	reader.mu.Lock()
	reader.evidence.ID++
	reader.evidence.Start++
	reader.mu.Unlock()
	for _, alias := range r.aliases {
		alias.expires = time.Time{}
	}
	for i, next := range trace {
		next.TCP.Seq += 1000
		if next.TCP.Ack != 0 {
			next.TCP.Ack += 1000
		}
		next.Timestamp = pkt.Timestamp.Add(time.Duration(i+1) * time.Millisecond)
		r.admit(e, next)
		processTransportAdmission(t, e, r)
	}
	if decoded() <= before || coverageLossCount(e) != 1 {
		t.Fatal("new table incarnation did not recover IEC decoding")
	}
	before = decoded()
	dropped.Timestamp = pkt.Timestamp.Add(time.Second)
	r.admit(e, dropped)
	notice = <-r.losses
	e.consumeDecodeLoss(notice, r.resolve(context.Background(), notice.packet, false))
	pkt.Payload = trace[4].Payload
	r.admit(e, pkt)
	processTransportAdmission(t, e, r)
	if decoded() != before || coverageLossCount(e) != 2 {
		t.Fatal("the recovered table incarnation did not stop on its own loss")
	}
	if !e.decodingStopped(e.tupleStateLocked(ev.Original)) {
		t.Fatal("retained legacy CT evidence repeatedly reopened the passive marker")
	}
}
