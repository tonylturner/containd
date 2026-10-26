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
	}
	f.e.hooks.onVerdict(pkt.Token, v, nil)
	return d
}

// synAck sends the server's handshake segment.
func (f *fcFlow) synAck() {
	f.t.Helper()
	if d := f.fromServer(0, capture.TCPFlagSYN|capture.TCPFlagACK); d.Action != capture.Accept {
		f.t.Fatalf("SYN-ACK decision = %+v, want Accept", d)
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
				if d := c.send(f); d.Action != capture.Accept {
					t.Fatalf("out-of-window close = %+v, want Accept", d)
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
				if d := c.send(f); d.Action != capture.Accept {
					t.Fatalf("in-window close = %+v, want Accept", d)
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
// client RST on the cached denial and by a server RST that passes: the
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
			if d := f.fromServer(0, capture.TCPFlagRST); d.Action != capture.Accept {
				t.Fatalf("server RST = %+v, want Accept", d)
			}
			f.e.verdictCache = NewVerdictCache(time.Minute, 16)
			f.failedClosed("read on the failed stream", f.decide(f.next, ackPsh, p.read(3)), p.name+"-read", failClosedStream, 1)
		})
	}
}

// TestResyncSYNOnLiveStream sends a SYN with a new sequence number after
// the head of a read and then the crafted rest: an enforce flow fails
// closed at the SYN and stays failed, a learn flow re-anchors and passes
// as before. An identical SYN retransmission changes nothing.
func TestResyncSYNOnLiveStream(t *testing.T) {
	for _, tc := range misframeCases() {
		crafted := concatFrames(tc.read[8:], tc.command)
		t.Run(tc.name+"/enforce", func(t *testing.T) {
			f := newModeFlow(t, "enforce", tc.port)
			f.syn()
			f.accept("read head", tc.read[:8])
			scope := tc.proto + "-read"
			f.failedClosed("SYN with a new sequence number", f.decide(8, capture.TCPFlagSYN, nil), scope, failClosedResync, 0)
			f.dropCachedAt(8, "crafted segment", crafted)
			f.e.verdictCache = NewVerdictCache(time.Minute, 16)
			f.failedClosed("crafted segment on the failed stream", f.decide(8, ackPsh, crafted), scope, failClosedResync, 1)
		})
		t.Run(tc.name+"/learn", func(t *testing.T) {
			f := newModeFlow(t, "learn", tc.port)
			f.syn()
			f.accept("read head", tc.read[:8])
			if d := f.decide(8, capture.TCPFlagSYN, nil); d.Action != capture.Accept {
				t.Fatalf("SYN under learn rules = %+v, want Accept", d)
			}
			f.acceptAt(8, "crafted segment", crafted)
			f.noBlock("learn")
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

// TestResyncMidStreamPickupInspected keeps inspecting an enforce flow whose
// stream is picked up mid-connection, without a handshake: from a frame
// boundary its reads are allowed and its prohibited commands denied; inside
// a frame it is framed from the first byte seen, and bytes that cannot
// start a frame fail closed.
func TestResyncMidStreamPickupInspected(t *testing.T) {
	for _, p := range firstCommandProtocols() {
		t.Run(p.name+"/at a frame boundary", func(t *testing.T) {
			f := newModeFlow(t, "enforce", p.port)
			f.isn = 3_000_000
			hits := ruleHits(f.e, p.name+"-read")
			f.accept("first read seen", p.read(4))
			if got := ruleHits(f.e, p.name+"-read"); got != hits+1 {
				t.Fatalf("read rule hits %d -> %d, want the read decoded", hits, got)
			}
			c := p.denied[0]
			f.deny("denied", c.rule, c.frame)
		})
		t.Run(p.name+"/inside a frame", func(t *testing.T) {
			f := newModeFlow(t, "enforce", p.port)
			f.isn = 3_000_000
			f.failedClosed("tail of a read", f.decide(0, ackPsh, p.read(4)[4:]), p.name+"-read", failClosedStream, 0)
		})
	}
}
