// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package dpi

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

// The tests in this file cover the ways a fail-closed legacy stream could
// otherwise resynchronize: a FIN or RST the receiver ignores, a SYN with a
// new sequence number, and a decoder panic. The mock framer's frames are a
// length byte followed by that many bytes.

func synSeg(seq uint32, failClosed bool) *ParsedPacket {
	p := tcpSeg(seq)
	p.TCPSyn, p.FailClosed = true, failClosed
	return p
}

func finSeg(seq uint32, payload ...byte) *ParsedPacket {
	p := failClosedSeg(seq, payload...)
	p.TCPFin = true
	return p
}

func rstSeg(seq uint32, payload ...byte) *ParsedPacket {
	p := failClosedSeg(seq, payload...)
	p.TCPRst = true
	return p
}

// wantFrames requires a clean parse of exactly the frame ranges.
func wantFrames(t *testing.T, what string, res InspectResult, want ...frameRange) {
	t.Helper()
	if want == nil {
		want = []frameRange{}
	}
	if res.Err != nil || !reflect.DeepEqual(ranges(res), want) {
		t.Fatalf("%s: Err=%v frames=%v, want frames %v", what, res.Err, ranges(res), want)
	}
}

func wantClose(t *testing.T, what string, mgr *Manager, st *flow.State, pkt *ParsedPacket, want bool) {
	t.Helper()
	ended, _, err := mgr.CloseStream(st, pkt)
	if err != nil || ended != want {
		t.Fatalf("%s: CloseStream = %v, %v; want %v", what, ended, err, want)
	}
}

// A fail-closed stream ignores a FIN or RST out of window and keeps its
// partial frame; a FIN right after its bytes ends it.
func TestCloseStreamOutOfWindowKeepsFailClosedStream(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  *ParsedPacket
	}{
		{"RST ahead", rstSeg(500)},
		{"RST behind", rstSeg(100)},
		{"RST with payload ending at the next byte", rstSeg(101, 0xA1)},
		{"FIN ahead", finSeg(500)},
		{"FIN before the held bytes' end", finSeg(101)},
		{"FIN beyond a hole", finSeg(110, 0x00)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr, _, st := framedFixture()
			mgr.Inspect(st, synSeg(100, true))
			wantFrames(t, "partial frame", mgr.Inspect(st, failClosedSeg(100, 0x02, 0xA1)))
			wantFrames(t, "close segment", mgr.Inspect(st, tc.pkt))
			wantClose(t, "close", mgr, st, tc.pkt, false)
			wantFrames(t, "frame tail", mgr.Inspect(st, failClosedSeg(102, 0xA2)), frameRange{0, 3})
			wantClose(t, "FIN in window", mgr, st, finSeg(103), true)
			if streams, held := mgr.reassembler.stats(); streams != 1 || held != 0 {
				t.Fatalf("closed stream: %d streams, %d bytes held", streams, held)
			}
		})
	}
}

// A FIN in window may carry the stream's last bytes; a RST's payload is
// never fed, so it must sit at the next sequence number itself.
func TestCloseStreamInWindow(t *testing.T) {
	mgr, _, st := framedFixture()
	mgr.Inspect(st, synSeg(100, true))
	fin := finSeg(100, 0x00, 0x01)
	wantFrames(t, "FIN with payload", mgr.Inspect(st, fin), frameRange{0, 1})
	wantClose(t, "FIN after its payload", mgr, st, fin, true)
	wantClose(t, "FIN retransmission", mgr, st, fin, false)
	wantClose(t, "RST at the FIN's sequence number", mgr, st, rstSeg(102), false)
	wantClose(t, "RST following the FIN", mgr, st, rstSeg(103), true)

	mgr, _, st = framedFixture()
	mgr.Inspect(st, synSeg(100, true))
	wantFrames(t, "frame", mgr.Inspect(st, failClosedSeg(100, 0x00)), frameRange{0, 1})
	rst := rstSeg(101, 0x01)
	wantFrames(t, "RST payload", mgr.Inspect(st, rst))
	wantClose(t, "RST at the next byte", mgr, st, rst, true)
}

// After an in-window close the stream takes no more bytes, since its
// receiver delivers none, and a SYN anchors a new stream normally (port
// reuse). Without fail-closed a segment after the close starts a new
// stream.
func TestCloseStreamThenNewConnection(t *testing.T) {
	mgr, _, st := framedFixture()
	mgr.Inspect(st, synSeg(100, true))
	wantFrames(t, "frame", mgr.Inspect(st, failClosedSeg(100, 0x00)), frameRange{0, 1})
	wantClose(t, "FIN", mgr, st, finSeg(101), true)
	wantFrames(t, "data after the FIN", mgr.Inspect(st, failClosedSeg(102, 0xFF)))
	wantFrames(t, "retransmitted data before the FIN", mgr.Inspect(st, failClosedSeg(100, 0x00)))
	if res := mgr.Inspect(st, synSeg(9000, true)); res.Err != nil {
		t.Fatalf("SYN of the next connection: %v", res.Err)
	}
	wantFrames(t, "first frame of the next connection", mgr.Inspect(st, failClosedSeg(9000, 0x01, 0xAA)), frameRange{0, 2})

	wantClose(t, "FIN of the next connection", mgr, st, finSeg(9002), true)
	wantFrames(t, "legacy segment after the FIN", mgr.Inspect(st, tcpSeg(9003, 0x00)), frameRange{0, 1})
}

// A RST in window ends the opposite direction too; one out of window ends
// neither.
func TestResetStreamEndsPeer(t *testing.T) {
	mgr, _, st := framedFixture()
	peer := flow.NewState(st.Key.Reversed(), time.Now())
	mgr.Inspect(st, synSeg(100, true))
	mgr.Inspect(peer, synSeg(700, true))
	wantFrames(t, "peer partial frame", mgr.Inspect(peer, failClosedSeg(700, 0x02, 0xB1)))
	wantClose(t, "RST out of window", mgr, st, rstSeg(300), false)
	wantClose(t, "RST in window", mgr, st, rstSeg(100), true)
	if _, err := mgr.ResetStream(peer, rstSeg(100)); err != nil {
		t.Fatal(err)
	}
	if _, held := mgr.reassembler.stats(); held != 0 {
		t.Fatalf("peer stream holds %d bytes after the reset", held)
	}
	wantClose(t, "peer RST at its next byte", mgr, peer, rstSeg(702), true)
}

// No close ends a failed stream, and a packet that does not fail closed
// does not end a fail-closed stream; other streams end at any FIN or RST.
func TestCloseStreamKeepsFailedAndFailClosedStreams(t *testing.T) {
	mgr, _, st := framedFixture()
	peer := flow.NewState(st.Key.Reversed(), time.Now())
	mgr.Inspect(st, synSeg(100, true))
	failed := mgr.Inspect(st, failClosedSeg(100, 0xFF))
	if failed.Err == nil {
		t.Fatal("unframeable bytes did not fail")
	}
	mgr.Inspect(peer, synSeg(700, true))
	mgr.Inspect(peer, failClosedSeg(700, 0x02, 0xB1))
	for _, pkt := range []*ParsedPacket{rstSeg(100), finSeg(100), {Proto: "tcp", TCPRst: true}} {
		wantClose(t, "close of the failed stream", mgr, st, pkt, false)
		if evs, err := mgr.ResetStream(st, pkt); evs != nil || err != nil {
			t.Fatalf("ResetStream of the failed stream = %v, %v", evs, err)
		}
	}
	if res := mgr.Inspect(st, failClosedSeg(101, 0x00)); res.Err != failed.Err {
		t.Fatalf("after the closes Err = %v, want the stream still failed", res.Err)
	}
	legacyRST := &ParsedPacket{Proto: "tcp", TCPRst: true, TCPSeq: 702, TCPSeqValid: true}
	wantClose(t, "legacy RST of the fail-closed peer", mgr, peer, legacyRST, false)
	wantFrames(t, "peer frame tail", mgr.Inspect(peer, failClosedSeg(702, 0xB2)), frameRange{0, 3})

	legacy := flow.NewState(flow.Key{SrcPort: 1}, time.Now())
	mgr.Inspect(legacy, tcpSeg(100, 0x02, 0xC1))
	wantClose(t, "legacy FIN out of window", mgr, legacy, &ParsedPacket{Proto: "tcp", TCPFin: true, TCPSeq: 900, TCPSeqValid: true}, true)
	wantFrames(t, "legacy stream restarted", mgr.Inspect(legacy, tcpSeg(102, 0x00)), frameRange{0, 1})
}

// A SYN with a new sequence number on a live fail-closed stream is a
// resync error that fails the stream; its retransmission is ignored, and a
// legacy stream re-anchors as before.
func TestOpenSYNOnLiveStream(t *testing.T) {
	mgr, _, st := framedFixture()
	mgr.Inspect(st, synSeg(100, true))
	wantFrames(t, "partial frame", mgr.Inspect(st, failClosedSeg(100, 0x02, 0xA1)))
	if res := mgr.Inspect(st, synSeg(100, true)); res.Err != nil || len(res.Events) != 0 {
		t.Fatalf("SYN retransmission Err=%v events=%v", res.Err, res.Events)
	}
	res := mgr.Inspect(st, synSeg(102, true))
	var se *StreamError
	if !errors.As(res.Err, &se) || se.Kind != StreamResync || se.Offset != 2 || se.Proto != "mock" || !res.Framed {
		t.Fatalf("SYN with a new sequence number Err = %v, want a mock resync at 2", res.Err)
	}
	wantMalformedLast(t, res, "mock")
	if again := mgr.Inspect(st, failClosedSeg(102, 0x00)); again.Err != res.Err || len(again.Events) != 0 {
		t.Fatalf("after the resync Err=%v events=%v, want the stream failed", again.Err, again.Events)
	}
	if again := mgr.Inspect(st, synSeg(5000, true)); again.Err != res.Err {
		t.Fatalf("SYN on the failed stream Err = %v, want it still failed", again.Err)
	}

	mgr, _, st = framedFixture()
	mgr.Inspect(st, synSeg(100, false))
	mgr.Inspect(st, tcpSeg(100, 0x02, 0xA1))
	if res := mgr.Inspect(st, synSeg(102, false)); res.Err != nil {
		t.Fatalf("legacy SYN Err = %v", res.Err)
	}
	wantFrames(t, "legacy stream re-anchored", mgr.Inspect(st, tcpSeg(102, 0x00)), frameRange{0, 1})
}

func wantMidStream(t *testing.T, what string, res InspectResult) {
	t.Helper()
	var se *StreamError
	if !errors.As(res.Err, &se) || se.Kind != StreamMidStream || se.Proto != "mock" || !res.Framed || len(res.Frames) != 0 || len(res.Events) != 0 {
		t.Fatalf("%s: Err=%v frames=%v events=%v, want a mock mid-stream failure and nothing parsed", what, res.Err, ranges(res), res.Events)
	}
}

// A fail-closed stream picked up mid-connection fails without parsing a
// byte and stays failed: without a handshake, after its flow's end, and
// after the idle sweep dropped its partial frame. Session streams and
// streams that do not fail closed are framed from their first byte.
func TestInspectFailsMidStreamPickup(t *testing.T) {
	mgr, _, st := framedFixture()
	first := mgr.Inspect(st, failClosedSeg(100, 0x00))
	wantMidStream(t, "first segment without a handshake", first)
	if again := mgr.Inspect(st, failClosedSeg(101, 0x00)); again.Err != first.Err {
		t.Fatalf("after the pickup Err = %v, want the stream failed", again.Err)
	}
	if res := mgr.Inspect(st, &ParsedPacket{Proto: "tcp", FailClosed: true}); res.Err != first.Err {
		t.Fatalf("segment without payload Err = %v, want the stream failed", res.Err)
	}
	if _, held := mgr.reassembler.stats(); held != 0 {
		t.Fatalf("picked-up stream holds %d bytes", held)
	}

	if _, err := mgr.OnFlowEnd(st); err != nil {
		t.Fatal(err)
	}
	wantMidStream(t, "first segment after the flow's end", mgr.Inspect(st, failClosedSeg(300, 0x00)))

	if _, err := mgr.OnFlowEnd(st); err != nil {
		t.Fatal(err)
	}
	mgr.Inspect(st, synSeg(200, true))
	wantFrames(t, "frame and partial frame", mgr.Inspect(st, failClosedSeg(200, 0x00, 0x02, 0xA1)), frameRange{0, 1})
	mgr.reassembler.sweep(time.Now().Add(time.Hour))
	if _, held := mgr.reassembler.stats(); held != 0 {
		t.Fatalf("after the idle sweep %d bytes held", held)
	}
	wantMidStream(t, "frame tail after the idle sweep", mgr.Inspect(st, failClosedSeg(203, 0xA2, 0x00)))

	mgr, _, st = framedFixture()
	wantFrames(t, "legacy pickup", mgr.Inspect(st, tcpSeg(100, 0x00)), frameRange{0, 1})
	wantFrames(t, "session stream", mgr.Inspect(st, &ParsedPacket{Proto: "tcp", Payload: []byte{0x00}, HasOffset: true, Session: "s1", Dir: ClientToServer, FailClosed: true}), frameRange{0, 1})
}

// The idle sweep keeps a fail-closed stream that holds no partial frame:
// its next bytes still start a frame. A stream it left lost, swept while
// not failing closed, restarts as before.
func TestSweepKeepsFailClosedPosition(t *testing.T) {
	mgr, _, st := framedFixture()
	mgr.Inspect(st, synSeg(100, true))
	wantFrames(t, "frame", mgr.Inspect(st, failClosedSeg(100, 0x01, 0xAA)), frameRange{0, 2})
	mgr.reassembler.sweep(time.Now().Add(time.Hour))
	wantFrames(t, "frame after the idle sweep", mgr.Inspect(st, failClosedSeg(102, 0x00)), frameRange{2, 3})
	if streams, held := mgr.reassembler.stats(); streams != 1 || held != 1 {
		t.Fatalf("after the sweep %d streams, %d bytes held (history from the last frame only)", streams, held)
	}

	mgr, _, st = framedFixture()
	mgr.Inspect(st, synSeg(100, true))
	mgr.Inspect(st, failClosedSeg(100, 0x02, 0xA1))
	mgr.reassembler.sweep(time.Now().Add(time.Hour))
	wantFrames(t, "legacy segment on the lost stream", mgr.Inspect(st, tcpSeg(102, 0x00)), frameRange{0, 1})

	mgr.reassembler.sweep(time.Now().Add(2 * time.Hour))
	if streams, _ := mgr.reassembler.stats(); streams != 0 {
		t.Fatalf("after the sweep %d streams, want the idle legacy stream removed", streams)
	}
}

// A SYN on a stream that began without one and failed as picked up starts
// the client's next connection. A lost stream was live: a SYN on it is a
// resync, and once its next bytes failed it, a SYN leaves it failed.
func TestOpenAfterMidStreamPickup(t *testing.T) {
	mgr, _, st := framedFixture()
	wantMidStream(t, "pickup", mgr.Inspect(st, failClosedSeg(100, 0x00)))
	if res := mgr.Inspect(st, synSeg(5000, true)); res.Err != nil {
		t.Fatalf("SYN of the next connection Err = %v", res.Err)
	}
	wantFrames(t, "first frame of the next connection", mgr.Inspect(st, failClosedSeg(5000, 0x00)), frameRange{0, 1})

	mgr, _, st = framedFixture()
	mgr.Inspect(st, synSeg(100, true))
	mgr.Inspect(st, failClosedSeg(100, 0x02, 0xA1))
	mgr.reassembler.sweep(time.Now().Add(time.Hour))
	res := mgr.Inspect(st, synSeg(7000, true))
	var se *StreamError
	if !errors.As(res.Err, &se) || se.Kind != StreamResync {
		t.Fatalf("SYN on the lost stream Err = %v, want a resync", res.Err)
	}

	mgr, _, st = framedFixture()
	mgr.Inspect(st, synSeg(100, true))
	mgr.Inspect(st, failClosedSeg(100, 0x02, 0xA1))
	mgr.reassembler.sweep(time.Now().Add(time.Hour))
	lost := mgr.Inspect(st, failClosedSeg(102, 0xA2))
	wantMidStream(t, "bytes after the lost frame", lost)
	if again := mgr.Inspect(st, synSeg(7000, true)); again.Err != lost.Err {
		t.Fatalf("SYN after the lost stream failed Err = %v, want it still failed", again.Err)
	}
}

// FailStream drops the buffered bytes of a stream whose decoder panicked
// and keeps it failed until its flow ends.
func TestFailStreamKeepsStreamFailed(t *testing.T) {
	mgr, _, st := framedFixture()
	mgr.Inspect(st, synSeg(100, true))
	wantFrames(t, "frame and partial frame", mgr.Inspect(st, failClosedSeg(100, 0x00, 0x02, 0xA1)), frameRange{0, 1})
	mgr.FailStream(st, failClosedSeg(102))
	if _, held := mgr.reassembler.stats(); held != 0 {
		t.Fatalf("failed stream holds %d bytes", held)
	}
	res := mgr.Inspect(st, failClosedSeg(103, 0xA2))
	var se *StreamError
	if !errors.As(res.Err, &se) || se.Kind != StreamDecoderPanic || se.Offset != 1 || se.Proto != "mock" || !res.Framed || len(res.Frames) != 0 {
		t.Fatalf("after FailStream Err=%v frames=%v, want the mock decoder panic at 1", res.Err, ranges(res))
	}
	mgr.reassembler.sweep(time.Now().Add(time.Hour))
	if again := mgr.Inspect(st, failClosedSeg(104, 0x00)); again.Err != res.Err {
		t.Fatalf("after the idle sweep Err = %v, want the stream still failed", again.Err)
	}
	if _, err := mgr.OnFlowEnd(st); err != nil {
		t.Fatal(err)
	}
	mgr.Inspect(st, synSeg(105, true))
	wantFrames(t, "after the flow's end", mgr.Inspect(st, failClosedSeg(105, 0x00)), frameRange{0, 1})

	// The panic may come before the stream holds anything.
	mgr, _, st = framedFixture()
	mgr.FailStream(st, failClosedSeg(100))
	if res := mgr.Inspect(st, failClosedSeg(100, 0x00)); !errors.As(res.Err, &se) || se.Kind != StreamDecoderPanic {
		t.Fatalf("FailStream without a stream: Err = %v", res.Err)
	}

	// Without a framing decoder there is no stream to fail.
	plain := NewManager(&countingDecoder{})
	plain.FailStream(st, failClosedSeg(100))
	if streams, _ := plain.reassembler.stats(); streams != 0 {
		t.Fatalf("FailStream without a framer created %d streams", streams)
	}
}

// countingDecoder is a packet decoder without stream framing.
type countingDecoder struct{ calls int }

func (d *countingDecoder) Supports(*flow.State) bool { return true }
func (d *countingDecoder) OnPacket(*flow.State, *ParsedPacket) ([]Event, error) {
	d.calls++
	return nil, nil
}
func (d *countingDecoder) OnFlowEnd(*flow.State) ([]Event, error) { return nil, nil }
