// SPDX-License-Identifier: Apache-2.0

package dpi

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestCaptureEventTime(t *testing.T) {
	at := time.Unix(1234567890, 123456789)
	mgr, _, st := framedFixture()
	for _, ts := range []time.Time{at, at.Add(-time.Hour)} {
		pkt := &ParsedPacket{Proto: "tcp", Payload: []byte{1, 42}, Timestamp: ts}
		res := mgr.Inspect(st, pkt)
		if len(res.Events) == 0 || len(res.Frames) == 0 {
			t.Fatal("fixture emitted no events")
		}
		for _, ev := range append(res.Events, res.Frames[0].Events...) {
			if !ev.Timestamp.Equal(ts) {
				t.Fatalf("timestamp = %v, want %v", ev.Timestamp, ts)
			}
		}
	}
	// A manager-generated malformed event takes the same capture time.
	bounded := smallManager(1, &mockStreamDecoder{})
	res := bounded.Inspect(st, &ParsedPacket{Proto: "tcp", Payload: []byte{9, 1}, Timestamp: at})
	if ev := wantMalformedLast(t, res, "mock"); !ev.Timestamp.Equal(at) {
		t.Fatalf("malformed timestamp = %v", ev.Timestamp)
	}
	// Decoder-generated malformed events and their FrameError agree too.
	framer := &scriptedFramer{parse: func(v StreamView) (StreamResult, error) {
		return StreamResult{}, &FrameError{Offset: v.Base, Event: Event{Kind: "malformed"}}
	}}
	res = NewManager(framer).Inspect(st, &ParsedPacket{Proto: "tcp", Payload: []byte{1}, Timestamp: at})
	if len(res.Events) != 1 || !res.Events[0].Timestamp.Equal(at) || !res.Err.(*FrameError).Event.Timestamp.Equal(at) {
		t.Fatalf("framing timestamps = %+v", res)
	}
}

func TestPacketAndFlowEndEventTime(t *testing.T) {
	at := time.Unix(1234567890, 42)
	d := &flowEndDecoder{event: Event{Kind: "end"}}
	st := flow.NewState(flow.Key{}, at)
	mgr := NewManager(d)
	events, err := mgr.OnFlowEnd(st)
	if err != nil || len(events) != 1 || !events[0].Timestamp.Equal(at) {
		t.Fatalf("flow end = %+v, %v", events, err)
	}
	lastAt := at.Add(-time.Minute)
	mgr.Inspect(st, &ParsedPacket{Timestamp: lastAt})
	events, err = mgr.OnFlowEnd(st)
	if err != nil || len(events) != 1 || !events[0].Timestamp.Equal(lastAt) || len(mgr.eventTimes) != 0 {
		t.Fatalf("last packet flow end = %+v, %v", events, err)
	}
	closedAt := at.Add(time.Minute)
	_, events, err = mgr.CloseStream(st, &ParsedPacket{Proto: "tcp", TCPFin: true, Timestamp: closedAt})
	if err != nil || len(events) != 1 || !events[0].Timestamp.Equal(closedAt) {
		t.Fatalf("close = %+v, %v", events, err)
	}
	if eventTime(nil, nil).IsZero() {
		t.Fatal("missing metadata produced a zero timestamp")
	}
}
