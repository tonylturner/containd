// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package modbus

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

var (
	readADU  = []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02} // FC 3, 12 bytes
	writeADU = []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0x2A} // FC 6, 12 bytes
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

func modbusState() *flow.State {
	return flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 502), time.Now())
}

func seg(seq uint32, payload []byte) *dpi.ParsedPacket {
	return &dpi.ParsedPacket{Proto: "tcp", SrcPort: 12345, DstPort: 502, Payload: payload, TCPSeq: seq, TCPSeqValid: true}
}

func TestParseStreamFramesEveryADU(t *testing.T) {
	stream := concat(readADU, writeADU, writeADU[:5])
	res, err := NewDecoder().ParseStream(modbusState(), dpi.StreamView{Session: "s", Base: 1000, Bytes: stream})
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if got := spans(res.Frames); !reflect.DeepEqual(got, []span{{1000, 1012}, {1012, 1024}}) {
		t.Fatalf("frames %v", got)
	}
	if res.Consumed != 24 || !res.NeedMore {
		t.Fatalf("Consumed=%d NeedMore=%v", res.Consumed, res.NeedMore)
	}
	fc0, _ := eventfields.Uint8(res.Frames[0].Events[0].Attributes, eventfields.KeyFunctionCode)
	fc1, _ := eventfields.Uint8(res.Frames[1].Events[0].Attributes, eventfields.KeyFunctionCode)
	if fc0 != 3 || fc1 != 6 {
		t.Fatalf("function codes %d, %d", fc0, fc1)
	}
	if got := res.Frames[1].Events[0].Attributes["raw_hex"]; got != "00020000000601060001002a" {
		t.Fatalf("raw_hex %v is not the ADU's own bytes", got)
	}
}

func TestParseStreamSplitAtEveryByte(t *testing.T) {
	stream := concat(readADU, writeADU, []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01})
	decodertest.CheckSplits(t, NewDecoder(), modbusState(), dpi.StreamView{Session: "s", Base: 40, Bytes: stream})
}

func TestParseStreamFrameError(t *testing.T) {
	bad := []byte{0x00, 0x03, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03} // MBAP length 256
	for _, tc := range []struct {
		name   string
		stream []byte
	}{
		{"length above 254", concat(readADU, bad)},
		{"length below 2", concat(readADU, []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01})},
	} {
		res, err := NewDecoder().ParseStream(modbusState(), dpi.StreamView{Base: 10, Bytes: tc.stream})
		var fe *dpi.FrameError
		if !errors.As(err, &fe) || fe.Offset != 22 {
			t.Fatalf("%s: err = %v, want *FrameError at 22", tc.name, err)
		}
		if got := spans(res.Frames); !reflect.DeepEqual(got, []span{{10, 22}}) || res.Consumed != 12 {
			t.Fatalf("%s: frames %v consumed %d", tc.name, got, res.Consumed)
		}
		if fe.Event.Kind != eventfields.KindMalformed || fe.Event.Proto != eventfields.ProtoModbus {
			t.Fatalf("%s: event %+v", tc.name, fe.Event)
		}
		if msg, ok := eventfields.String(fe.Event.Attributes, eventfields.KeyError); !ok || msg == "" {
			t.Fatalf("%s: malformed event without error", tc.name)
		}
	}
}

// Every cut point of two coalesced ADUs, through the DPI manager that trims
// the consumed prefix: each ADU is decoded exactly once, at the packet that
// completes it.
func TestManagerSplitAtEveryByte(t *testing.T) {
	stream := concat(readADU, writeADU)
	for cut := 1; cut < len(stream); cut++ {
		mgr := dpi.NewManager(NewDecoder())
		st := modbusState()
		first := mgr.Inspect(st, seg(5000, stream[:cut]))
		second := mgr.Inspect(st, seg(5000+uint32(cut), stream[cut:]))
		if first.Err != nil || second.Err != nil || !first.Framed {
			t.Fatalf("cut %d: errors %v / %v framed=%v", cut, first.Err, second.Err, first.Framed)
		}
		for _, f := range first.Frames {
			if f.End > int64(cut) {
				t.Fatalf("cut %d: frame %v decoded before it was complete", cut, f)
			}
		}
		all := append(spans(first.Frames), spans(second.Frames)...)
		if !reflect.DeepEqual(all, []span{{0, 12}, {12, 24}}) {
			t.Fatalf("cut %d: frames %v", cut, all)
		}
		if n := len(first.Events) + len(second.Events); n != 2 {
			t.Fatalf("cut %d: %d events", cut, n)
		}
	}
}

// A read followed by a write on one connection: the write is inspected and
// a retransmission of the read emits nothing (spec §4.1 item 7).
func TestManagerPersistentConnection(t *testing.T) {
	mgr := dpi.NewManager(NewDecoder())
	st := modbusState()
	steps := []struct {
		pkt  *dpi.ParsedPacket
		want []uint8
	}{
		{seg(100, readADU), []uint8{3}},
		{seg(100, readADU), nil},
		{seg(112, writeADU), []uint8{6}},
	}
	for i, step := range steps {
		res := mgr.Inspect(st, step.pkt)
		var got []uint8
		for _, ev := range res.Events {
			fc, _ := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode)
			got = append(got, fc)
		}
		if res.Err != nil || !reflect.DeepEqual(got, step.want) {
			t.Fatalf("step %d: function codes %v err %v, want %v", i, got, res.Err, step.want)
		}
	}
}

func TestOnPacketUsesStreamParser(t *testing.T) {
	st := modbusState()
	events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: concat(readADU, writeADU)})
	if err != nil || len(events) != 2 {
		t.Fatalf("coalesced: %d events, %v", len(events), err)
	}
	events, err = NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: concat(readADU, []byte{0, 0, 0, 0, 0xFF, 0xFF})})
	var fe *dpi.FrameError
	if !errors.As(err, &fe) || len(events) != 2 || events[1].Kind != eventfields.KindMalformed {
		t.Fatalf("unframeable: %d events, %v", len(events), err)
	}
	if events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: readADU[:7]}); err != nil || len(events) != 0 {
		t.Fatalf("partial ADU: %d events, %v", len(events), err)
	}
}

func TestProtocol(t *testing.T) {
	var sd dpi.StreamDecoder = NewDecoder()
	if sd.Protocol() != "modbus" {
		t.Fatalf("Protocol() = %q", sd.Protocol())
	}
}
