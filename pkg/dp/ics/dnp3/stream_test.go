// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

// Synthetic link frames (IEEE 1815-2012 data link frame format). Control
// 0xC4 is DIR|PRM unconfirmed user data from a master, 0x44 the same from an
// outstation.
func linkFrame(control uint8, userData []byte) []byte {
	return buildTestFrame(uint8(5+len(userData)), control, 0x0001, 0x0002, userData)
}

var (
	readFrame     = linkFrame(0xC4, []byte{0xC0, 0xC0, FuncRead, 0x3C, 0x02, 0x06})                // 10+6+2 = 18
	operateFrame  = linkFrame(0xC4, []byte{0xC1, 0xC1, FuncDirectOperate, 0x0C, 0x01, 0x07, 0x01}) // 10+7+2 = 19
	linkStatus    = linkFrame(0xC9, nil)                                                           // request link status, 10
	responseFrame = linkFrame(0x44, []byte{0x42, 0xC0, FuncResponse, 0x00, 0x00})                  // FIR, not FIN
	continuation  = linkFrame(0x44, []byte{0x83, 0x01, 0x02, 0x00, 0x00, 0x00, 0x81})              // FIN, not FIR
)

type span struct{ start, end int64 }

func spans(frames []dpi.DecodedFrame) []span {
	out := []span{}
	for _, f := range frames {
		out = append(out, span{f.Start, f.End})
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func dnp3State() *flow.State {
	return flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 20000), time.Now())
}

func TestParseStreamFramesEveryLinkFrame(t *testing.T) {
	stream := concat(readFrame, linkStatus, operateFrame, responseFrame, continuation, readFrame[:9])
	res, err := NewDecoder().ParseStream(dnp3State(), dpi.StreamView{Base: 100, Bytes: stream})
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	want := []span{{100, 118}, {118, 128}, {128, 147}, {147, 164}, {164, 183}}
	if got := spans(res.Frames); !reflect.DeepEqual(got, want) {
		t.Fatalf("frames %v, want %v", got, want)
	}
	if res.Consumed != 83 || !res.NeedMore {
		t.Fatalf("Consumed=%d NeedMore=%v", res.Consumed, res.NeedMore)
	}
	// Link-only frames and continuation segments carry no application header.
	perFrame := []struct {
		events    int
		fc        uint8
		direction string
	}{{1, FuncRead, "master"}, {0, 0, ""}, {1, FuncDirectOperate, "master"}, {1, FuncResponse, "outstation"}, {0, 0, ""}}
	for i, w := range perFrame {
		evs := res.Frames[i].Events
		if len(evs) != w.events {
			t.Fatalf("frame %d: %d events, want %d", i, len(evs), w.events)
		}
		if w.events == 0 {
			continue
		}
		fc, _ := eventfields.Uint8(evs[0].Attributes, eventfields.KeyFunctionCode)
		dir, _ := eventfields.String(evs[0].Attributes, eventfields.KeyDirection)
		if fc != w.fc || dir != w.direction {
			t.Fatalf("frame %d: fc %d direction %q, want %d %q", i, fc, dir, w.fc, w.direction)
		}
	}
	if got := res.Frames[0].Events[0].Attributes["raw_hex"]; got != hexOf(readFrame) {
		t.Fatalf("raw_hex %v is not the frame's own bytes", got)
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func TestParseStreamSplitAtEveryByte(t *testing.T) {
	stream := concat(readFrame, linkStatus, operateFrame, continuation, []byte{0x05, 0x64, 0x05, 0xC0, 1, 0, 2, 0, 0xFF, 0xFF})
	decodertest.CheckSplits(t, NewDecoder(), dnp3State(), dpi.StreamView{Base: 7, Bytes: stream})
}

func TestParseStreamFrameErrors(t *testing.T) {
	shortLen := []byte{0x05, 0x64, 0x04, 0xC0, 0x01, 0x00, 0x02, 0x00}
	shortLen = binary.LittleEndian.AppendUint16(shortLen, crc16DNP3(shortLen))
	cases := []struct {
		name string
		bad  []byte
		want error
	}{
		{"start octets", []byte{0x05, 0x65}, ErrInvalidStart},
		{"first start octet", []byte{0x64}, ErrInvalidStart},
		{"header CRC", []byte{0x05, 0x64, 0x05, 0xC0, 1, 0, 2, 0, 0xFF, 0xFF}, ErrBadHeaderCRC},
		{"length below 5", shortLen, ErrBadLength},
	}
	for _, tc := range cases {
		res, err := NewDecoder().ParseStream(dnp3State(), dpi.StreamView{Base: 0, Bytes: concat(readFrame, tc.bad)})
		var fe *dpi.FrameError
		if !errors.As(err, &fe) || fe.Offset != 18 || fe.Reason != tc.want.Error() {
			t.Fatalf("%s: err = %v, want FrameError at 18: %v", tc.name, err, tc.want)
		}
		if len(res.Frames) != 1 || res.Consumed != 18 {
			t.Fatalf("%s: frames %v consumed %d", tc.name, spans(res.Frames), res.Consumed)
		}
		if fe.Event.Kind != eventfields.KindMalformed || fe.Event.Proto != eventfields.ProtoDNP3 {
			t.Fatalf("%s: event %+v", tc.name, fe.Event)
		}
	}
}

// A read then a direct operate on one connection: the operate is inspected
// and a retransmitted read emits nothing (spec §4.1 item 7).
func TestManagerPersistentConnection(t *testing.T) {
	mgr := dpi.NewManager(NewDecoder())
	st := dnp3State()
	seg := func(seq uint32, payload []byte) *dpi.ParsedPacket {
		return &dpi.ParsedPacket{Proto: "tcp", Payload: payload, TCPSeq: seq, TCPSeqValid: true}
	}
	steps := []struct {
		pkt  *dpi.ParsedPacket
		want []uint8
	}{
		{seg(1, readFrame), []uint8{FuncRead}},
		{seg(1, readFrame), nil},
		{seg(19, concat(linkStatus, operateFrame)), []uint8{FuncDirectOperate}},
	}
	for i, step := range steps {
		res := mgr.Inspect(st, step.pkt)
		var got []uint8
		for _, ev := range res.Events {
			fc, _ := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode)
			got = append(got, fc)
		}
		if res.Err != nil || !res.Framed || !reflect.DeepEqual(got, step.want) {
			t.Fatalf("step %d: function codes %v err %v, want %v", i, got, res.Err, step.want)
		}
	}
}

func TestOnPacketUsesStreamParser(t *testing.T) {
	st := dnp3State()
	events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: concat(readFrame, operateFrame)})
	if err != nil || len(events) != 2 {
		t.Fatalf("coalesced: %d events, %v", len(events), err)
	}
	events, err = NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: concat(readFrame, []byte{0xFF})})
	var fe *dpi.FrameError
	if !errors.As(err, &fe) || len(events) != 2 || events[1].Kind != eventfields.KindMalformed {
		t.Fatalf("unframeable: %d events, %v", len(events), err)
	}
	if events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: readFrame[:12]}); err != nil || len(events) != 0 {
		t.Fatalf("partial frame: %d events, %v", len(events), err)
	}
}

func TestProtocol(t *testing.T) {
	var sd dpi.StreamDecoder = NewDecoder()
	if sd.Protocol() != "dnp3" {
		t.Fatalf("Protocol() = %q", sd.Protocol())
	}
}
