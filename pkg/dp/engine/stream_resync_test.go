// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

// The tests in this file try to move an inline enforce flow's stream off
// the server's framing without a stream error: a FIN or RST the server
// ignores, a SYN with a new sequence number, and a decoder panic. Were the
// stream restarted after the head of a read, the decoder would frame from
// the middle of the read and the prohibited command that follows would
// pass (as in TestFirstCommandAfterConflictingOverlap).

const resyncServerISN = 51000

type misframeCase struct {
	name    string
	proto   string
	port    uint16
	read    []byte
	command []byte
	rule    string // the deny rule the command hits
}

func misframeCases() []misframeCase {
	return []misframeCase{
		// Transaction ID 0x00FE: the misframed MBAP length field.
		{"modbus fc6 write", "modbus", 502, modbusADU(1, 3, 0, 2), modbusADU(0x00FE, 6, 1, 0x1234), "modbus-write-deny"},
		{"dnp3 fc5 direct operate", "dnp3", dnp3Port, dnp3Request(1, 1, []byte{0x3C, 0x01, 0x06}), dnp3Operate(5, 9), "dnp3-operate-deny"},
	}
}

// fromServer hands one server segment at payload offset off to the engine
// as the inline capture does and completes its verdict.
func (f *fcFlow) fromServer(off uint32, flags capture.TCPFlags) capture.Decision {
	pkt := connSegment(true, f.client, f.port, resyncServerISN+off, flags, nil)
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	d := f.e.HandlePacket(pkt)
	v := capture.VerdictAccept
	if d.Action == capture.Drop {
		v = capture.VerdictDrop
	} else if d.Action == capture.Repeat {
		v = capture.VerdictRepeat
	}
	f.e.hooks.onVerdict(pkt.Token, v, nil)
	return d
}

// synAck sends the server's handshake segment.
func (f *fcFlow) synAck() {
	f.t.Helper()
	if d := f.fromServer(0, capture.TCPFlagSYN|capture.TCPFlagACK); d.Action != capture.Repeat {
		f.t.Fatalf("SYN-ACK decision = %+v, want Repeat", d)
	}
}

type closeCase struct {
	name string
	send func(f *fcFlow) capture.Decision
}

const finAck = capture.TCPFlagFIN | capture.TCPFlagACK

// TestResyncOutOfWindowCloseKeepsStream sends a FIN or RST the server
// ignores after the head of a read: the stream keeps its partial frame and
// the segment completing the prohibited command is dropped.
func TestResyncOutOfWindowCloseKeepsStream(t *testing.T) {
	closes := []closeCase{
		{"client RST ahead", func(f *fcFlow) capture.Decision { return f.decide(f.next+4096, capture.TCPFlagRST, nil) }},
		{"client RST behind", func(f *fcFlow) capture.Decision { return f.decide(2, capture.TCPFlagRST, nil) }},
		{"client FIN ahead", func(f *fcFlow) capture.Decision { return f.decide(f.next+4096, finAck, nil) }},
		{"server RST ahead", func(f *fcFlow) capture.Decision { return f.fromServer(4096, capture.TCPFlagRST) }},
	}
	for _, tc := range misframeCases() {
		for _, c := range closes {
			t.Run(tc.name+"/"+c.name, func(t *testing.T) {
				f := newModeFlow(t, "enforce", tc.port)
				f.syn()
				f.synAck()
				f.accept("read head", tc.read[:8])
				if d := c.send(f); d.Action != capture.Repeat {
					t.Fatalf("out-of-window close = %+v, want Repeat", d)
				}
				f.denyAt(8, "segment completing "+tc.name, tc.rule, concatFrames(tc.read[8:], tc.command))
			})
		}
	}
}

// TestResyncInWindowCloseThenNewConnection ends the connection in window;
// a new connection on the same tuple anchors at its SYN, its reads are
// allowed and its prohibited commands still denied.
func TestResyncInWindowCloseThenNewConnection(t *testing.T) {
	closes := []closeCase{
		{"client FIN", func(f *fcFlow) capture.Decision { return f.decide(f.next, finAck, nil) }},
		{"client RST", func(f *fcFlow) capture.Decision { return f.decide(f.next, capture.TCPFlagRST, nil) }},
		{"server RST", func(f *fcFlow) capture.Decision { return f.fromServer(0, capture.TCPFlagRST) }},
	}
	for _, p := range firstCommandProtocols() {
		for _, c := range closes {
			t.Run(p.name+"/"+c.name, func(t *testing.T) {
				f := newModeFlow(t, "enforce", p.port)
				f.syn()
				f.synAck()
				f.accept("read 1", p.read(1))
				f.accept("read 2 head", p.read(2)[:5])
				if d := c.send(f); d.Action != capture.Repeat {
					t.Fatalf("in-window close = %+v, want Repeat", d)
				}
				f.isn, f.next = 900000, 0
				f.syn()
				hits := ruleHits(f.e, p.name+"-read")
				f.accept("read on the new connection", p.read(3))
				if got := ruleHits(f.e, p.name+"-read"); got != hits+1 {
					t.Fatalf("read rule hits %d -> %d, want the read decoded", hits, got)
				}
				f.noBlock("new connection")
				c := p.denied[0]
				f.deny("denied on the new connection", c.rule, c.frame)
			})
		}
	}
}

// TestResyncCloseKeepsFailedStream closes a failed stream in window, by a
// client RST and a server RST, both dropped by the tuple tombstone: the
// stream stays failed once the cached denial has expired.
func TestResyncCloseKeepsFailedStream(t *testing.T) {
	for _, p := range firstCommandProtocols() {
		t.Run(p.name, func(t *testing.T) {
			f := newModeFlow(t, "enforce", p.port)
			f.syn()
			f.synAck()
			f.accept("read 1", p.read(1))
			bad := malformedRead(p, 2)
			f.failedClosed("malformed read", f.decide(f.next, ackPsh, bad), p.name+"-read", failClosedStream, 0)
			f.next += uint32(len(bad))
			if d := f.decide(f.next, capture.TCPFlagRST, nil); d.Action != capture.Drop || d.Reason != reasonCachedDeny {
				t.Fatalf("client RST on the denied flow = %+v, want the cached denial", d)
			}
			if d := f.fromServer(0, capture.TCPFlagRST); d.Action != capture.Drop {
				t.Fatalf("server RST = %+v, want Drop", d)
			}
			f.e.verdictCache = NewVerdictCache(time.Minute, 16)
			f.failedClosed("read on the failed stream", f.decide(f.next, ackPsh, p.read(3)), p.name+"-read", failClosedStream, 1)
		})
	}
}

// TestResyncSYNOnLiveStream sends a SYN with a new sequence number after
// the head of a read and then the crafted rest. A SYN without payload
// neither fails the stream nor blocks the flow. Sent into the established connection, the SYN
// leaves the stream's framing: the read completes and the command is
// denied. As the handshake of a new connection on the tuple, it leaves the
// stream lost, so the crafted rest drops as a pickup. A SYN that carries
// the crafted rest fails the flow closed. A learn flow re-anchors and
// passes as before; an identical SYN retransmission changes nothing.
func TestResyncSYNOnLiveStream(t *testing.T) {
	for _, tc := range misframeCases() {
		crafted := concatFrames(tc.read[8:], tc.command)
		scope := tc.proto + "-read"
		t.Run(tc.name+"/enforce SYN into the connection", func(t *testing.T) {
			f := newModeFlow(t, "enforce", tc.port)
			f.syn()
			f.accept("read head", tc.read[:8])
			if d := f.establishedSyn(8); d.Action != capture.Repeat {
				t.Fatalf("SYN into the connection = %+v, want Repeat", d)
			}
			f.noBlock("SYN into the connection")
			f.denyAt(8, "segment completing "+tc.name, tc.rule, crafted)
		})
		t.Run(tc.name+"/enforce SYN of a new handshake", func(t *testing.T) {
			f := newModeFlow(t, "enforce", tc.port)
			f.syn()
			f.accept("read head", tc.read[:8])
			if d := f.decide(8, capture.TCPFlagSYN, nil); d.Action != capture.Repeat {
				t.Fatalf("handshake SYN on the live stream = %+v, want Repeat", d)
			}
			f.noBlock("handshake SYN")
			f.pickedUp("crafted segment", f.decide(8, ackPsh, crafted), scope, 0)
		})
		t.Run(tc.name+"/enforce SYN with data", func(t *testing.T) {
			f := newModeFlow(t, "enforce", tc.port)
			f.syn()
			f.accept("read head", tc.read[:8])
			f.failedClosed("SYN carrying the crafted rest", f.decide(8, capture.TCPFlagSYN, crafted), scope, failClosedResync, 0)
			f.dropCachedAt(8, "crafted segment", crafted)
		})
		t.Run(tc.name+"/learn", func(t *testing.T) {
			f := newModeFlow(t, "monitor", tc.port)
			f.syn()
			f.accept("read head", tc.read[:8])
			if d := f.decide(8, capture.TCPFlagSYN, nil); d.Action != capture.Repeat {
				t.Fatalf("SYN under learn rules = %+v, want Accept", d)
			}
			f.acceptAt(8, "crafted segment", crafted)
			f.noBlock("monitor")
		})
		t.Run(tc.name+"/retransmitted SYN", func(t *testing.T) {
			f := newModeFlow(t, "enforce", tc.port)
			f.syn()
			f.accept("read head", tc.read[:8])
			f.syn()
			f.noBlock("SYN retransmission")
			f.denyAt(8, "segment completing "+tc.name, tc.rule, crafted)
		})
	}
}

// panicOnceFramer panics on its first ParseStream call and frames as its
// decoder afterwards.
type panicOnceFramer struct {
	dpi.StreamDecoder
	panicked atomic.Bool
}

func (p *panicOnceFramer) ParseStream(state *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	if p.panicked.CompareAndSwap(false, true) {
		panic("decoder bug")
	}
	return p.StreamDecoder.ParseStream(state, v)
}

// TestResyncPanicKeepsStreamFailed panics while the stream holds the head
// of a read. Past the cached denial the benign tail of that read is not
// framed with the bytes buffered before the panic: the stream stays
// failed.
func TestResyncPanicKeepsStreamFailed(t *testing.T) {
	f := newModeFlow(t, "enforce", 502)
	f.e.dpiMgr = dpi.NewManager(&panicOnceFramer{StreamDecoder: modbus.NewDecoder()})
	f.syn()
	read := modbusADU(1, 3, 0, 2)
	f.failedClosed("decoder panic", f.decide(0, ackPsh, read[:8]), "modbus-read", failClosedPanic, 0)
	f.dropCachedAt(8, "read tail", read[8:])
	f.e.verdictCache = NewVerdictCache(time.Minute, 16)
	f.failedClosed("read tail on the failed stream", f.decide(8, ackPsh, read[8:]), "modbus-read", failClosedPanic, 1)
}

// pickedUp requires the drop of a stream picked up mid-connection, its
// original stream_midstream decision and no dynamic block retry.
func (f *fcFlow) pickedUp(what string, d capture.Decision, rule string, before int) {
	f.t.Helper()
	if d.Action != capture.Drop || (before == 0 && d.Reason != reasonStreamFailClosed) {
		f.t.Fatalf("%s: decision = %+v, want Drop by %s", what, d, reasonStreamFailClosed)
	}
	evs := failClosedEvents(f.e)
	if len(evs) != 1 {
		f.t.Fatalf("%s: fail-closed events %d -> %d, want the one original decision", what, before, len(evs))
	}
	ev := evs[0] // newest first
	if ev.Attributes[eventfields.KeyRuleID] != rule || ev.Attributes[eventfields.KeyReason] != failClosedMidStream ||
		ev.Attributes[eventfields.KeyDecision] != decisionDeny || ev.Attributes[eventfields.KeyMode] != "enforce" {
		f.t.Fatalf("%s: event attributes %v, want deny by %s for %s", what, ev.Attributes, rule, failClosedMidStream)
	}
	select {
	case got := <-f.up.calls:
		f.t.Fatalf("%s: dynamic block %q for a mid-stream pickup", what, got)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestResyncMidStreamPickupDropped picks up an enforce flow
// mid-connection, as after an engine restart or once the engine forgot an
// idle flow: its packets drop until the flow ends, without a flow block.
// The client's next connection, on a new or the same source port, is
// inspected from its first byte.
func TestResyncMidStreamPickupDropped(t *testing.T) {
	pickups := []struct {
		name string
		lose func(f *fcFlow, p firstCommandProtocol)
	}{
		{"connection seen after its handshake", func(*fcFlow, firstCommandProtocol) {}},
		{"flow swept while idle", func(f *fcFlow, p firstCommandProtocol) {
			f.syn()
			f.accept("read before the sweep", p.read(1))
			f.e.sweepFlows(time.Now().Add(time.Hour))
		}},
	}
	for _, p := range firstCommandProtocols() {
		for _, pc := range pickups {
			for _, reconnect := range []string{"new source port", "same source port"} {
				t.Run(p.name+"/"+pc.name+"/"+reconnect, func(t *testing.T) {
					f := newModeFlow(t, "enforce", p.port)
					pc.lose(f, p)
					rule := p.name + "-read"
					f.pickedUp("read on the picked-up stream", f.decide(f.next, ackPsh, p.read(2)), rule, 0)
					f.dropCachedAt(f.next, "read after the pickup", p.read(2))
					f.e.verdictCache = NewVerdictCache(time.Minute, 16)
					f.pickedUp("read past the cached denial", f.decide(f.next, ackPsh, p.read(2)), rule, 1)
					if reconnect == "new source port" {
						f.client++
					}
					f.isn, f.next = 800000, 0
					f.syn()
					hits := ruleHits(f.e, rule)
					f.accept("read on the next connection", p.read(3))
					if got := ruleHits(f.e, rule); got != hits+1 {
						t.Fatalf("read rule hits %d -> %d, want the read decoded", hits, got)
					}
					c := p.denied[0]
					f.deny("denied on the next connection", c.rule, c.frame)
				})
			}
		}
		t.Run(p.name+"/learn", func(t *testing.T) {
			f := newModeFlow(t, "monitor", p.port)
			hits := shadowHits(f.e, p.name+"-read")
			f.accept("read without a handshake", p.read(1))
			if got := shadowHits(f.e, p.name+"-read"); got != hits+1 {
				t.Fatalf("read rule hits %d -> %d, want the read decoded", hits, got)
			}
			f.noBlock("monitor")
		})
	}
}

// TestResyncMidStreamPickupDropsFirstCommand sends a prohibited command as
// the first payload of a connection seen without its handshake: it is
// dropped as a mid-stream pickup, whatever the updater does.
func TestResyncMidStreamPickupDropsFirstCommand(t *testing.T) {
	for _, mode := range []string{"ok", "failing", "stalled"} {
		for _, p := range firstCommandProtocols() {
			for _, c := range p.denied {
				t.Run(mode+"/"+p.name+"/"+c.name, func(t *testing.T) {
					f := newFCFlow(t, mode, p.port)
					f.pickedUp("denied without a handshake", f.decide(0, ackPsh, c.frame), p.name+"-read", 0)
				})
			}
		}
	}
}

// decisionEvents counts the ics.decision events.
func decisionEvents(e *Engine) int {
	n := 0
	for _, ev := range e.Events().List(0) {
		if ev.Kind == eventfields.KindDecision {
			n++
		}
	}
	return n
}

// TestResyncDeniedStreamStaysDenied denies a command with an updater that
// would fail or stall if called. Past the cached denial the retransmitted command
// (bytes the stream already consumed) and every later packet of the
// connection still drop, without another decision event or rule hit, until
// the flow ends; the client's next connection is inspected as usual.
func TestResyncDeniedStreamStaysDenied(t *testing.T) {
	for _, mode := range []string{"failing", "stalled"} {
		for _, p := range firstCommandProtocols() {
			t.Run(mode+"/"+p.name, func(t *testing.T) {
				f := newFCFlow(t, mode, p.port)
				f.syn()
				f.accept("read", p.read(1))
				c := p.denied[0]
				at := f.next
				f.deny("denied", c.rule, c.frame)
				hits, decisions := ruleHits(f.e, c.rule), decisionEvents(f.e)
				for _, step := range []struct {
					what    string
					off     uint32
					payload []byte
				}{
					{"retransmitted command", at, c.frame},
					{"read after the command", f.next, p.read(2)},
				} {
					f.e.verdictCache = NewVerdictCache(time.Minute, 16)
					if d := f.decide(step.off, ackPsh, step.payload); d.Action != capture.Drop {
						t.Fatalf("%s past the cached denial = %+v, want Drop by %s", step.what, d, reasonDPIDeny)
					}
				}
				if got := ruleHits(f.e, c.rule); got != hits {
					t.Fatalf("deny rule hits %d -> %d, want no new hit", hits, got)
				}
				if got := decisionEvents(f.e); got != decisions {
					t.Fatalf("decision events %d -> %d, want none for the same denial", decisions, got)
				}
				f.client++
				f.isn, f.next = 800000, 0
				f.syn()
				f.accept("read on the next connection", p.read(3))
			})
		}
	}
}
