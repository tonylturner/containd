// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// scriptedFramer returns a fixed ParseStream result.
type scriptedFramer struct {
	mockStreamDecoder
	parse func(v StreamView) (StreamResult, error)
}

func (s *scriptedFramer) ParseStream(_ *flow.State, v StreamView) (StreamResult, error) {
	return s.parse(v)
}

func smallManager(maxSize int, decs ...Decoder) *Manager {
	m := NewManager(decs...)
	m.reassembler = newReassembler(maxSize, time.Minute)
	return m
}

func wantMalformedLast(t *testing.T, res InspectResult, proto string) Event {
	t.Helper()
	if len(res.Events) == 0 {
		t.Fatal("no events")
	}
	ev := res.Events[len(res.Events)-1]
	if ev.Kind != "malformed" || ev.Proto != proto {
		t.Fatalf("last event = %+v, want %s malformed", ev, proto)
	}
	if msg, ok := eventfields.String(ev.Attributes, eventfields.KeyError); !ok || msg != res.Err.Error() {
		t.Fatalf("error attribute = %q, want %q", msg, res.Err.Error())
	}
	return ev
}

// Without sequence numbers every message on a
// persistent connection is decoded once, in arrival order.
func TestInspectAppendModeDecodesEveryMessage(t *testing.T) {
	mgr, _, st := framedFixture()
	noSeq := func(b ...byte) *ParsedPacket { return &ParsedPacket{Proto: "tcp", Payload: b} }
	first := mgr.Inspect(st, noSeq(0x01, 0xA1))
	second := mgr.Inspect(st, noSeq(0x01, 0xB1))
	third := mgr.Inspect(st, noSeq(0x01))
	fourth := mgr.Inspect(st, noSeq(0xC1))
	got := [][]frameRange{ranges(first), ranges(second), ranges(third), ranges(fourth)}
	want := [][]frameRange{{{0, 2}}, {{2, 4}}, {}, {{4, 6}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("frames %v, want %v", got, want)
	}
}

func TestInspectStreamOverflowLegacyRestarts(t *testing.T) {
	mgr := smallManager(4, &mockStreamDecoder{})
	st := flow.NewState(flow.Key{}, time.Now())
	mgr.Inspect(st, tcpSeg(0, 0x09, 1, 2))
	res := mgr.Inspect(st, tcpSeg(3, 3, 4))
	var se *StreamError
	if !errors.As(res.Err, &se) || se.Kind != StreamOverflow || se.Offset != 3 || se.Proto != "mock" {
		t.Fatalf("Err = %v, want mock overflow at 3", res.Err)
	}
	if !res.Framed || len(res.Frames) != 0 {
		t.Fatalf("Framed=%v frames=%v", res.Framed, ranges(res))
	}
	wantMalformedLast(t, res, "mock")
	// The buffer was discarded: a legacy stream starts fresh.
	fresh := mgr.Inspect(st, tcpSeg(5, 0x00))
	if fresh.Err != nil || !reflect.DeepEqual(ranges(fresh), []frameRange{{0, 1}}) {
		t.Fatalf("fresh Err=%v frames=%v", fresh.Err, ranges(fresh))
	}
}

func TestInspectOverlapConflictFailsSessionUntilEndStream(t *testing.T) {
	mgr, _, st := framedFixture()
	const session = "run-9"
	mgr.Inspect(st, sessionSeg(session, ClientToServer, 0, 0x02, 0xA1))
	res := mgr.Inspect(st, sessionSeg(session, ClientToServer, 1, 0xEE, 0xA2))
	var se *StreamError
	if !errors.As(res.Err, &se) || se.Kind != StreamOverlapConflict || se.Offset != 1 {
		t.Fatalf("Err = %v, want overlap conflict at 1", res.Err)
	}
	ev := wantMalformedLast(t, res, "mock")
	if sid, _ := eventfields.String(ev.Attributes, eventfields.KeySessionID); sid != session {
		t.Fatalf("session_id = %q", sid)
	}
	after := mgr.Inspect(st, sessionSeg(session, ClientToServer, 2, 0xA2))
	if !after.Framed || after.Err != res.Err || len(after.Events) != 0 {
		t.Fatalf("failed stream: Framed=%v Err=%v events=%d", after.Framed, after.Err, len(after.Events))
	}
	// The other direction is unaffected.
	if srv := mgr.Inspect(st, sessionSeg(session, ServerToClient, 0, 0x00)); srv.Err != nil || len(srv.Frames) != 1 {
		t.Fatalf("server direction: Err=%v frames=%v", srv.Err, ranges(srv))
	}
	mgr.EndStream(session)
	if again := mgr.Inspect(st, sessionSeg(session, ClientToServer, 0, 0x00)); again.Err != nil || len(again.Frames) != 1 {
		t.Fatalf("after EndStream: Err=%v frames=%v", again.Err, ranges(again))
	}
}

// Out-of-order session data waits behind the hole, then parses in order.
func TestInspectSessionOutOfOrderParsesWhenFilled(t *testing.T) {
	mgr, _, st := framedFixture()
	held := mgr.Inspect(st, sessionSeg("s", ClientToServer, 2, 0x00))
	if !held.Gap || len(held.Frames) != 0 || len(held.Events) != 0 {
		t.Fatalf("gap=%v frames=%v events=%d", held.Gap, ranges(held), len(held.Events))
	}
	filled := mgr.Inspect(st, sessionSeg("s", ClientToServer, 0, 0x01, 0xAA))
	if filled.Gap || !reflect.DeepEqual(ranges(filled), []frameRange{{0, 2}, {2, 3}}) {
		t.Fatalf("gap=%v frames=%v", filled.Gap, ranges(filled))
	}
}

func TestInspectWrapsNonFrameError(t *testing.T) {
	boom := errors.New("decoder bug")
	dec := &scriptedFramer{parse: func(v StreamView) (StreamResult, error) {
		return StreamResult{Frames: []DecodedFrame{{Start: v.Base, End: v.Base + 1, Events: []Event{{Kind: "dropped"}}}}, Consumed: 1}, boom
	}}
	mgr := NewManager(dec)
	st := flow.NewState(flow.Key{}, time.Now())
	res := mgr.Inspect(st, sessionSeg("s", ServerToClient, 0, 1, 2))
	var fe *FrameError
	if !errors.As(res.Err, &fe) || fe.Offset != 0 || fe.Reason != boom.Error() {
		t.Fatalf("Err = %v, want FrameError at the view base", res.Err)
	}
	if len(res.Frames) != 0 || len(res.Events) != 1 {
		t.Fatalf("frames=%v events=%+v, want only the synthesized malformed event", ranges(res), res.Events)
	}
	wantMalformedLast(t, res, "mock")
}

func TestInspectRejectsFramingContractViolations(t *testing.T) {
	cases := map[string]func(v StreamView) StreamResult{
		"gap between frames": func(v StreamView) StreamResult {
			return StreamResult{Frames: []DecodedFrame{{Start: v.Base, End: v.Base + 1}, {Start: v.Base + 2, End: v.Base + 3}}, Consumed: 3}
		},
		"not from base": func(v StreamView) StreamResult {
			return StreamResult{Frames: []DecodedFrame{{Start: v.Base + 1, End: v.Base + 2}}, Consumed: 2}
		},
		"beyond view": func(v StreamView) StreamResult {
			return StreamResult{Frames: []DecodedFrame{{Start: v.Base, End: v.Base + 9}}, Consumed: 9}
		},
		"consumed partial frame": func(v StreamView) StreamResult {
			return StreamResult{Consumed: 1}
		},
		"empty frame": func(v StreamView) StreamResult {
			return StreamResult{Frames: []DecodedFrame{{Start: v.Base, End: v.Base}}}
		},
	}
	for name, parse := range cases {
		t.Run(name, func(t *testing.T) {
			mgr := NewManager(&scriptedFramer{parse: func(v StreamView) (StreamResult, error) { return parse(v), nil }})
			res := mgr.Inspect(flow.NewState(flow.Key{}, time.Now()), tcpSeg(0, 1, 2, 3))
			var fe *FrameError
			if !errors.As(res.Err, &fe) || fe.Offset != 0 || len(res.Frames) != 0 {
				t.Fatalf("Err=%v frames=%v, want FrameError at 0 and no frames", res.Err, ranges(res))
			}
			wantMalformedLast(t, res, "mock")
		})
	}
}

func TestInspectFrameErrorWithoutEventGetsOne(t *testing.T) {
	mgr := NewManager(&scriptedFramer{parse: func(v StreamView) (StreamResult, error) {
		return StreamResult{}, &FrameError{Offset: v.Base, Reason: "bad start octet"}
	}})
	res := mgr.Inspect(flow.NewState(flow.Key{}, time.Now()), tcpSeg(0, 1))
	wantMalformedLast(t, res, "mock")
}

// Packet decoders never allocate stream buffers or produce stream errors.
func TestInspectLegacyStreamHasNoStreamErrors(t *testing.T) {
	dec := &mockDecoder{support: true}
	mgr := smallManager(4, dec)
	st := flow.NewState(flow.Key{}, time.Now())
	mgr.Inspect(st, tcpSeg(0, 1, 2, 3))
	for _, pkt := range []*ParsedPacket{tcpSeg(3, 4, 5), tcpSeg(1, 9)} {
		if res := mgr.Inspect(st, pkt); res.Err != nil || res.Framed {
			t.Fatalf("legacy stream: Err=%v Framed=%v", res.Err, res.Framed)
		}
	}
}

func TestInspectLegacyDecoderErrorPassesThrough(t *testing.T) {
	boom := errors.New("legacy parse error")
	mgr := NewManager(&erroringDecoder{err: boom})
	st := flow.NewState(flow.Key{}, time.Now())
	res := mgr.Inspect(st, tcpSeg(0, 1))
	if res.Err != boom || len(res.Events) != 1 {
		t.Fatalf("Err=%v events=%d, want the legacy error unchanged with its events", res.Err, len(res.Events))
	}
	// The next segment is independent, and its error also passes through.
	res = mgr.Inspect(st, tcpSeg(1, 2))
	if res.Err != boom || len(res.Events) != 1 {
		t.Fatalf("next segment: %+v", res)
	}
	if streams, held := mgr.reassembler.stats(); streams != 0 || held != 0 {
		t.Fatalf("stats = %d streams, %d bytes; packet decoders must not buffer", streams, held)
	}
}

// Frame events come first, then the error's malformed event, once.
func TestInspectFrameEventsPrecedeErrorEvent(t *testing.T) {
	mgr, _, st := framedFixture()
	res := mgr.Inspect(st, tcpSeg(0, 0x00, 0x01, 0xAA, 0xFF))
	if len(res.Events) != 3 || res.Events[0].Kind != "test-frame" || res.Events[1].Kind != "test-frame" || res.Events[2].Kind != "malformed" {
		t.Fatalf("events %+v", res.Events)
	}
}

type erroringDecoder struct{ err error }

func (d *erroringDecoder) Supports(*flow.State) bool { return true }
func (d *erroringDecoder) OnPacket(*flow.State, *ParsedPacket) ([]Event, error) {
	return []Event{{Kind: "partial"}}, d.err
}
func (d *erroringDecoder) OnFlowEnd(*flow.State) ([]Event, error) { return nil, nil }
