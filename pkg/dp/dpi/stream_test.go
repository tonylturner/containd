// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

type frameRange struct{ start, end int64 }

func ranges(res InspectResult) []frameRange {
	out := []frameRange{}
	for _, f := range res.Frames {
		out = append(out, frameRange{f.Start, f.End})
	}
	return out
}

func framedFixture() (*Manager, *mockStreamDecoder, *flow.State) {
	dec := &mockStreamDecoder{}
	return NewManager(dec), dec, flow.NewState(flow.Key{}, time.Now())
}

func tcpSeg(seq uint32, payload ...byte) *ParsedPacket {
	return &ParsedPacket{Proto: "tcp", Payload: payload, TCPSeq: seq, TCPSeqValid: true}
}

func sessionSeg(session string, dir StreamDir, offset int64, payload ...byte) *ParsedPacket {
	return &ParsedPacket{Proto: "tcp", Payload: payload, HasOffset: true, Offset: offset, Session: session, Dir: dir}
}

// Two frames split over three packets with a trim between them give
// [0,n1) and [n1,n1+n2); no event comes from a partial frame.
func TestInspectFramedAbsoluteRangesAcrossTrim(t *testing.T) {
	mgr, dec, st := framedFixture()
	// frame 1: 02 A1 A2 (3 bytes); frame 2: 03 B1 B2 B3 (4 bytes)
	steps := []struct {
		pkt      *ParsedPacket
		want     []frameRange
		needMore bool
	}{
		{tcpSeg(1000, 0x02, 0xA1), []frameRange{}, true},
		{tcpSeg(1002, 0xA2, 0x03, 0xB1), []frameRange{{0, 3}}, true},
		{tcpSeg(1005, 0xB2, 0xB3), []frameRange{{3, 7}}, false},
	}
	for i, step := range steps {
		res := mgr.Inspect(st, step.pkt)
		if res.Err != nil || !res.Framed || res.Proto != "mock" {
			t.Fatalf("step %d: Err=%v Framed=%v Proto=%q", i, res.Err, res.Framed, res.Proto)
		}
		if got := ranges(res); !reflect.DeepEqual(got, step.want) {
			t.Fatalf("step %d: frames %v, want %v", i, got, step.want)
		}
		if len(res.Events) != len(step.want) || res.NeedMore != step.needMore || res.Gap {
			t.Fatalf("step %d: events=%d needMore=%v gap=%v", i, len(res.Events), res.NeedMore, res.Gap)
		}
	}
	if dec.onPacketCalls != 0 {
		t.Fatalf("framed decoder OnPacket called %d times on TCP", dec.onPacketCalls)
	}
}

func TestInspectFramedRetransmissionEmitsOnce(t *testing.T) {
	mgr, _, st := framedFixture()
	first := mgr.Inspect(st, tcpSeg(0, 0x01, 0xAA, 0x01))
	if got := ranges(first); !reflect.DeepEqual(got, []frameRange{{0, 2}}) {
		t.Fatalf("first frames %v", got)
	}
	// Retransmission of the consumed frame plus the pending tail byte.
	again := mgr.Inspect(st, tcpSeg(0, 0x01, 0xAA, 0x01))
	if len(again.Events) != 0 || len(again.Frames) != 0 {
		t.Fatalf("retransmission re-emitted %d events / %d frames", len(again.Events), len(again.Frames))
	}
	done := mgr.Inspect(st, tcpSeg(3, 0xBB))
	if got := ranges(done); !reflect.DeepEqual(got, []frameRange{{2, 4}}) {
		t.Fatalf("completing frames %v", got)
	}
}

func TestInspectFramedCoalescedFramesAndConsumed(t *testing.T) {
	mgr, _, st := framedFixture()
	res := mgr.Inspect(st, tcpSeg(0, 0x00, 0x01, 0xAA, 0x02))
	if got := ranges(res); !reflect.DeepEqual(got, []frameRange{{0, 1}, {1, 3}}) {
		t.Fatalf("frames %v", got)
	}
	if !res.NeedMore || len(res.Events) != 2 {
		t.Fatalf("needMore=%v events=%d", res.NeedMore, len(res.Events))
	}
	// Only the complete prefix was trimmed: the tail continues at offset 3.
	next := mgr.Inspect(st, tcpSeg(4, 0xB1, 0xB2))
	if got := ranges(next); !reflect.DeepEqual(got, []frameRange{{3, 6}}) {
		t.Fatalf("tail frames %v", got)
	}
}

func TestInspectFramedGapParsesNothingBeyondHole(t *testing.T) {
	mgr, _, st := framedFixture()
	mgr.Inspect(st, tcpSeg(0, 0x02, 0xA1))
	res := mgr.Inspect(st, tcpSeg(5, 0x00))
	if !res.Gap || len(res.Frames) != 0 || !res.NeedMore {
		t.Fatalf("gap=%v frames=%v needMore=%v", res.Gap, ranges(res), res.NeedMore)
	}
	filled := mgr.Inspect(st, tcpSeg(2, 0xA2, 0x01, 0xB1))
	if got := ranges(filled); !reflect.DeepEqual(got, []frameRange{{0, 3}, {3, 5}, {5, 6}}) || filled.Gap {
		t.Fatalf("filled frames %v gap=%v", got, filled.Gap)
	}
}

func TestInspectFrameErrorDiscardsLegacyStream(t *testing.T) {
	mgr, _, st := framedFixture()
	res := mgr.Inspect(st, tcpSeg(0, 0x01, 0xAA, 0xFF, 0x00))
	var fe *FrameError
	if !errors.As(res.Err, &fe) || fe.Offset != 2 {
		t.Fatalf("Err = %v, want *FrameError at 2", res.Err)
	}
	if got := ranges(res); !reflect.DeepEqual(got, []frameRange{{0, 2}}) {
		t.Fatalf("frames before the error %v", got)
	}
	if len(res.Events) != 2 || res.Events[0].Kind != "test-frame" || res.Events[1].Kind != "malformed" {
		t.Fatalf("events %+v, want frame event then malformed event", res.Events)
	}
	// OnPacket returns the same events and error.
	_, err := NewManager(&mockStreamDecoder{}).OnPacket(st, tcpSeg(0, 0xFF))
	if !errors.As(err, &fe) {
		t.Fatalf("OnPacket err = %v, want *FrameError", err)
	}
	// A legacy stream starts fresh with the next packet.
	fresh := mgr.Inspect(st, tcpSeg(4, 0x00))
	if fresh.Err != nil || !reflect.DeepEqual(ranges(fresh), []frameRange{{0, 1}}) {
		t.Fatalf("fresh stream Err=%v frames=%v", fresh.Err, ranges(fresh))
	}
}

func TestInspectSessionStreamOffsetsAndFailure(t *testing.T) {
	mgr, _, st := framedFixture()
	const session = "run-1"
	res := mgr.Inspect(st, sessionSeg(session, ClientToServer, 0, 0x01, 0xAA, 0x02))
	if got := ranges(res); !reflect.DeepEqual(got, []frameRange{{0, 2}}) {
		t.Fatalf("c frames %v", got)
	}
	// The other direction is an independent stream with its own offsets;
	// every session stream starts at offset 0, the first byte after the SYN,
	// so a first segment at 100 waits behind a gap.
	srv := mgr.Inspect(st, sessionSeg(session, ServerToClient, 100, 0x00))
	if got := ranges(srv); len(got) != 0 || !srv.Gap {
		t.Fatalf("s frames %v gap=%v, want a gap before offset 100", got, srv.Gap)
	}

	bad := mgr.Inspect(st, sessionSeg(session, ClientToServer, 3, 0xA1, 0xA2, 0xFF))
	var fe *FrameError
	if !errors.As(bad.Err, &fe) || fe.Offset != 5 || len(bad.Events) != 2 {
		t.Fatalf("Err=%v events=%d, want *FrameError at 5 with 2 events", bad.Err, len(bad.Events))
	}
	// Failed until EndStream: no parsing, no repeated events.
	after := mgr.Inspect(st, sessionSeg(session, ClientToServer, 6, 0x00))
	if !after.Framed || after.Err != bad.Err || len(after.Events) != 0 || len(after.Frames) != 0 {
		t.Fatalf("failed stream: Framed=%v Err=%v events=%d", after.Framed, after.Err, len(after.Events))
	}
	mgr.EndStream(session)
	reopened := mgr.Inspect(st, sessionSeg(session, ClientToServer, 0, 0x00))
	if reopened.Err != nil || !reflect.DeepEqual(ranges(reopened), []frameRange{{0, 1}}) {
		t.Fatalf("after EndStream Err=%v frames=%v", reopened.Err, ranges(reopened))
	}
}

func TestInspectSessionWithoutIdentityIsNotFramed(t *testing.T) {
	mgr, _, st := framedFixture()
	for _, pkt := range []*ParsedPacket{
		sessionSeg("", ClientToServer, 0, 0x00),
		sessionSeg("run-1", DirUnknown, 0, 0x00),
	} {
		if res := mgr.Inspect(st, pkt); res.Framed || len(res.Events) != 0 {
			t.Fatalf("HasOffset without Session/Dir: Framed=%v events=%d", res.Framed, len(res.Events))
		}
	}
}

func TestInspectHandsDecoderAnOwnedCopy(t *testing.T) {
	mgr, dec, st := framedFixture()
	dec.scribble = true
	mgr.Inspect(st, tcpSeg(0, 0x02, 0xA1))
	res := mgr.Inspect(st, tcpSeg(2, 0xA2))
	if got := ranges(res); !reflect.DeepEqual(got, []frameRange{{0, 3}}) {
		t.Fatalf("frames %v after decoder scribbled on its view", got)
	}
}

func TestInspectLegacyDecoderOnly(t *testing.T) {
	dec := &mockDecoder{support: true}
	mgr := NewManager(dec)
	res := mgr.Inspect(flow.NewState(flow.Key{}, time.Now()), tcpSeg(0, 0x01))
	if res.Framed || res.Proto != "" || res.Err != nil || dec.calls != 1 {
		t.Fatalf("legacy Inspect: %+v calls=%d", res, dec.calls)
	}
}

func TestStreamErrorStrings(t *testing.T) {
	se := &StreamError{Kind: StreamOverlapConflict, Offset: 9, Proto: "iec104"}
	if got := se.Error(); got != "dpi: iec104 stream overlap_conflict at offset 9" {
		t.Fatalf("StreamError = %q", got)
	}
	fe := &FrameError{Offset: 4, Reason: "bad start octet"}
	if got := fe.Error(); got != "dpi: cannot frame stream at offset 4: bad start octet" {
		t.Fatalf("FrameError = %q", got)
	}
	if StreamOverflow.String() != "overflow" || StreamOutOfOrderLimit.String() != "out_of_order_limit" {
		t.Fatal("StreamErrKind strings")
	}
}
