// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// resetFlow is an enforce flow whose engine resets connections through a
// fake injector, as an inline engine with its raw socket does.
type resetFlow struct {
	*fcFlow
	inj     *session.Fake
	deletes chan conntrack.DeleteRequest
}

func newResetFlow(t *testing.T, port uint16) *resetFlow {
	f := &resetFlow{fcFlow: newModeFlow(t, "enforce", port), inj: &session.Fake{}, deletes: make(chan conntrack.DeleteRequest, 8)}
	f.e.iec.injector = f.inj
	f.e.iec.health.clear(faultInjector)
	f.e.iec.ctDelete = func(_ context.Context, req conntrack.DeleteRequest) error {
		f.deletes <- req
		return nil
	}
	return f
}

// handle hands pkt to the engine as the inline capture does and completes
// its verdict.
func (f *resetFlow) handle(pkt capture.Packet) capture.Decision {
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	d := f.e.HandlePacket(pkt)
	v := capture.VerdictAccept
	if d.Action == capture.Drop {
		v = capture.VerdictDrop
	}
	f.e.hooks.onVerdict(pkt.Token, v, nil)
	return d
}

// segment is a segment of the connection at sequence number seq that
// acknowledges ack.
func (f *resetFlow) segment(fromServer bool, seq, ack uint32, flags capture.TCPFlags, payload []byte) capture.Packet {
	pkt := connSegment(fromServer, f.client, f.port, seq, flags, payload)
	pkt.TCP.Ack = ack
	return pkt
}

// waitResets waits for n resets and the conntrack delete that follows
// them.
func (f *resetFlow) waitResets(n int) []session.Reset {
	f.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(f.inj.Resets()) < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case req := <-f.deletes:
		want := conntrack.DeleteRequest{Proto: "tcp", Src: testClient, Dst: testServer, Sport: int(f.client), Dport: int(f.port)}
		if req != want {
			f.t.Fatalf("conntrack delete %+v, want %+v", req, want)
		}
	case <-time.After(2 * time.Second):
		f.t.Fatal("no conntrack delete after the resets")
	}
	return f.inj.Resets()
}

func (f *resetFlow) endpoints() (client, server netip.AddrPort) {
	return netip.MustParseAddrPort(testClient + ":" + strconv.Itoa(int(f.client))),
		netip.MustParseAddrPort(testServer + ":" + strconv.Itoa(int(f.port)))
}

// TestPickupResetOnce picks up a connection mid-stream, as after an engine
// restart: the server's ACK passes, the client's read drops and the
// connection is reset once, at both endpoints, at the sequence numbers the
// read shows. Later packets of either direction drop without another
// reset; the client's next connection on the same port is inspected from
// its handshake.
func TestPickupResetOnce(t *testing.T) {
	for _, p := range firstCommandProtocols() {
		t.Run(p.name, func(t *testing.T) {
			f := newResetFlow(t, p.port)
			const clientSeq, serverSeq = 7000, resyncServerISN + 1
			if d := f.handle(f.segment(true, serverSeq, clientSeq, capture.TCPFlagACK, nil)); d.Action != capture.Accept {
				t.Fatalf("server ACK of the picked-up connection = %+v, want Accept", d)
			}
			rule := p.name + "-read"
			f.pickedUp("read on the picked-up connection", f.handle(f.segment(false, clientSeq, serverSeq, ackPsh, p.read(1))), rule, 0)
			client, server := f.endpoints()
			want := []session.Reset{{Src: client, Dst: server, Seq: clientSeq}, {Src: server, Dst: client, Seq: serverSeq}}
			if got := f.waitResets(2); !reflect.DeepEqual(got, want) {
				t.Fatalf("resets %+v, want %+v", got, want)
			}

			f.e.verdictCache = NewVerdictCache(time.Minute, 16)
			f.pickedUp("read past the cached denial", f.handle(f.segment(false, clientSeq, serverSeq, ackPsh, p.read(1))), rule, 1)
			f.pickedUp("server data", f.handle(f.segment(true, serverSeq, clientSeq, ackPsh, p.read(2))), rule, 2)
			time.Sleep(50 * time.Millisecond)
			if got := len(f.inj.Resets()); got != 2 {
				t.Fatalf("%d resets, want one pair", got)
			}

			f.isn, f.next = 900000, 0
			f.syn()
			f.synAck()
			hits := ruleHits(f.e, rule)
			f.accept("read on the next connection", p.read(3))
			if got := ruleHits(f.e, rule); got != hits+1 {
				t.Fatalf("read rule hits %d -> %d, want the read decoded", hits, got)
			}
			c := p.denied[0]
			f.deny("denied on the next connection", c.rule, c.frame)
			time.Sleep(50 * time.Millisecond)
			if got := len(f.waitResets(4)); got != 4 {
				t.Fatalf("%d resets, want a pair for each denied connection", got)
			}
		})
	}
}

// TestPickupResetFailureIsUnhealthy keeps dropping a picked-up connection
// whose resets fail and reports the failure: in engine health while an
// enforce ICS rule is loaded, though no IEC104 envelope is.
func TestPickupResetFailureIsUnhealthy(t *testing.T) {
	f := newResetFlow(t, 502)
	reported := make(chan error, 8)
	f.e.iec.onError = func(err error) { reported <- err }
	f.inj.SetError(errors.New("sendto: operation not permitted"))
	f.pickedUp("read on the picked-up connection", f.handle(f.segment(false, 7000, 9000, ackPsh, modbusADU(1, 3, 0, 2))), "modbus-read", 0)
	f.waitResets(2)
	f.e.iec.health.mu.Lock()
	reason := f.e.iec.health.faults[faultReset]
	f.e.iec.health.mu.Unlock()
	if !strings.Contains(reason, "operation not permitted") || len(reported) != 2 {
		t.Fatalf("reset fault %q, %d errors reported; want both failed resets reported", reason, len(reported))
	}
	if st := f.e.IEC104Enforcement(); st.Active || st.Healthy || st.Reason != reason {
		t.Fatalf("health %+v, want unhealthy by %q without an active envelope", st, reason)
	}
	f.e.LoadRules(learnPolicy())
	if st := f.e.IEC104Enforcement(); !st.Healthy {
		t.Fatalf("health %+v under learn rules, want healthy", st)
	}
}

// TestPickupWithoutInjectorOnlyDrops keeps the drop without a flow block
// when no reset can be sent.
func TestPickupWithoutInjectorOnlyDrops(t *testing.T) {
	f := newResetFlow(t, 502)
	f.e.iec.health.fault(faultInjector, "reset injector unavailable")
	f.pickedUp("read on the picked-up connection", f.handle(f.segment(false, 7000, 9000, ackPsh, modbusADU(1, 3, 0, 2))), "modbus-read", 0)
	time.Sleep(50 * time.Millisecond)
	if got := f.inj.Resets(); len(got) != 0 {
		t.Fatalf("resets %+v without a ready injector", got)
	}
}

// TestReconnectOnSamePortAfterLostConnection loses the client's side of a
// connection, as a client that restarts without sending a RST does: its
// next SYN, on the same source port, is sent into the connection
// connection tracking still holds established. It passes without
// anchoring, failing or blocking anything; the server answers with a
// challenge ACK, the client's RST at it ends the old connection, and the
// SYN the client retransmits, now of a new handshake, starts the next
// connection, inspected from its first byte.
func TestReconnectOnSamePortAfterLostConnection(t *testing.T) {
	for _, p := range firstCommandProtocols() {
		t.Run(p.name, func(t *testing.T) {
			f := newResetFlow(t, p.port)
			f.syn()
			f.synAck()
			f.accept("read", p.read(1))
			f.accept("read head", p.read(2)[:5])
			rcvNext := f.isn + f.next // the server's receive point
			f.isn, f.next = 400000, 0
			if d := f.establishedSyn(0); d.Action != capture.Accept {
				t.Fatalf("reconnect SYN into the connection = %+v, want Accept", d)
			}
			if d := f.handle(f.segment(true, resyncServerISN, rcvNext, capture.TCPFlagACK, nil)); d.Action != capture.Accept {
				t.Fatalf("challenge ACK = %+v, want Accept", d)
			}
			if d := f.handle(f.segment(false, rcvNext, 0, capture.TCPFlagRST, nil)); d.Action != capture.Accept {
				t.Fatalf("client RST at the challenge ACK = %+v, want Accept", d)
			}
			f.syn()
			f.synAck()
			f.noBlock("reconnect")
			hits := ruleHits(f.e, p.name+"-read")
			f.accept("read on the next connection", p.read(3))
			if got := ruleHits(f.e, p.name+"-read"); got != hits+1 {
				t.Fatalf("read rule hits %d -> %d, want the read decoded", hits, got)
			}
			c := p.denied[0]
			f.deny("denied on the next connection", c.rule, c.frame)
			if got := f.waitResets(2); len(got) != 2 {
				t.Fatalf("resets %+v, want a pair for the new denial", got)
			}
		})
	}
}

// TestPickupResetAnswersChallengeACK resets a picked-up connection whose
// server ignores the RST at the read's sequence number: its challenge ACKs
// get the reset again at their ACK number, at most iecResetRetries times.
// A packet at the reset's own sequence number, or a RST, gets none.
func TestPickupResetAnswersChallengeACK(t *testing.T) {
	f := newResetFlow(t, 502)
	const clientSeq, serverSeq = 7000, resyncServerISN + 1
	f.pickedUp("read on the picked-up connection", f.handle(f.segment(false, clientSeq, serverSeq, ackPsh, modbusADU(1, 3, 0, 2))), "modbus-read", 0)
	f.waitResets(2)
	client, server := f.endpoints()
	f.handle(f.segment(true, serverSeq, clientSeq, capture.TCPFlagACK, nil))    // at the reset's sequence number
	f.handle(f.segment(true, serverSeq, clientSeq+40, capture.TCPFlagRST, nil)) // a RST
	for i := range uint32(iecResetRetries + 2) {
		f.handle(f.segment(true, serverSeq, clientSeq+12+i, capture.TCPFlagACK, nil)) // challenge ACKs
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(f.inj.Resets()) < 2+iecResetRetries && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	got := f.inj.Resets()[2:]
	want := []session.Reset{
		{Src: client, Dst: server, Seq: clientSeq + 12},
		{Src: client, Dst: server, Seq: clientSeq + 13},
		{Src: client, Dst: server, Seq: clientSeq + 14},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resets after the challenge ACKs %+v, want %+v", got, want)
	}
}
