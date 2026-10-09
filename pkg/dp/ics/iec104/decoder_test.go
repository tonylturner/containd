// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

// A client session: STARTDT act, GI, a select and execute of type 46, an
// S-frame and TESTFR con.
func clientStream() []byte {
	return cat(
		uFrame(startdtAct),
		iFrame(0, 0, asdu(100, 1, cotAct, 0, 1, cat(ioa(0), []byte{20})...)),
		iFrame(1, 3, asdu(46, 1, cotAct, 0, 1, cat(ioa(2001), []byte{0x82})...)),
		iFrame(2, 4, asdu(46, 1, cotAct, 0, 1, cat(ioa(2001), []byte{0x02})...)),
		sFrame(9),
		uFrame(testfrCon),
	)
}

// The server side: STARTDT con, GI confirmation, GI data with several
// objects per APDU, spontaneous timed data and the command confirmation.
func serverStream() []byte {
	return cat(
		uFrame(startdtCon),
		iFrame(0, 1, asdu(100, 1, cotActCon, 0, 1, cat(ioa(0), []byte{20})...)),
		iFrame(1, 1, asdu(3, vsqSQ|4, cotInrogen, 0, 1, cat(ioa(1001), []byte{1, 2, 0x81, 2})...)),
		iFrame(2, 1, asdu(13, 2, cotInrogen, 0, 1, cat(ioa(2001), f32(230.5), []byte{0}, ioa(2002), f32(-1), []byte{0x10})...)),
		iFrame(3, 1, asdu(31, 1, cotSpont, 0, 1, cat(ioa(3001), []byte{2}, courseTime)...)),
		iFrame(4, 2, asdu(46, 1, cotActCon, 0, 1, cat(ioa(2001), []byte{0x82})...)),
		iFrame(5, 3, asdu(100, 1, cotActTerm, 0, 1, cat(ioa(0), []byte{20})...)),
	)
}

func TestSupportsPortsProtocol(t *testing.T) {
	d := NewDecoder()
	var _ dpi.StreamDecoder = d
	if tcp, udp := d.Ports(); !reflect.DeepEqual(tcp, []uint16{2404}) || udp != nil {
		t.Fatalf("Ports() = %v %v", tcp, udp)
	}
	if d.Protocol() != "iec104" {
		t.Fatalf("Protocol() = %q", d.Protocol())
	}
	for _, tc := range []struct {
		key  flow.Key
		want bool
	}{
		{flow.Key{Proto: 6, SrcPort: 40000, DstPort: 2404}, true},
		{flow.Key{Proto: 6, SrcPort: 2404, DstPort: 40000}, true},
		{flow.Key{Proto: 6, SrcPort: 40000, DstPort: 2405}, false},
		{flow.Key{Proto: 17, SrcPort: 40000, DstPort: 2404}, false},
	} {
		if got := d.Supports(flow.NewState(tc.key, time.Now())); got != tc.want {
			t.Errorf("Supports(%+v) = %v", tc.key, got)
		}
	}
	if d.Supports(nil) {
		t.Fatal("Supports(nil)")
	}
	if evs, err := d.OnFlowEnd(iecState()); evs != nil || err != nil {
		t.Fatalf("OnFlowEnd = %v, %v", evs, err)
	}
}

// IDs come from the view: session_id is the view's session, apdu_id is
// session/direction/absolute start, shared by every object of the APDU.
func TestIDsAndDirection(t *testing.T) {
	for _, tc := range []struct {
		dir       dpi.StreamDir
		stream    []byte
		letter    string
		direction string
		kind      string
	}{
		{dpi.ClientToServer, clientStream(), "c", DirectionRequest, eventfields.KindRequest},
		{dpi.ServerToClient, serverStream(), "s", DirectionResponse, eventfields.KindResponse},
	} {
		res, err := NewDecoder().ParseStream(iecState(), view(tc.dir, 1_000_000, tc.stream))
		if err != nil || res.NeedMore || res.Consumed != len(tc.stream) {
			t.Fatalf("%s: err %v needMore %v consumed %d", tc.letter, err, res.NeedMore, res.Consumed)
		}
		for _, f := range res.Frames {
			want := testSession + "/" + tc.letter + "/" + strconv.FormatInt(f.Start, 10)
			for _, ev := range f.Events {
				a := ev.Attributes
				if a[eventfields.KeyAPDUID] != want || a[eventfields.KeySessionID] != testSession || a[eventfields.KeyDirection] != tc.direction {
					t.Fatalf("%s frame %d: ids %v %v %v", tc.letter, f.Start, a[eventfields.KeyAPDUID], a[eventfields.KeySessionID], a[eventfields.KeyDirection])
				}
				if a[eventfields.KeyAPCIType] == "I" && ev.Kind != tc.kind {
					t.Fatalf("%s frame %d: kind %s (%v)", tc.letter, f.Start, ev.Kind, a[eventfields.KeyError])
				}
				if ev.Proto != "iec104" || ev.FlowID != iecState().Key.Hash() {
					t.Fatalf("proto %q flow %q", ev.Proto, ev.FlowID)
				}
			}
		}
	}
	// 1 STARTDT + 1 GI con + 4 + 2 + 1 + 1 + 1 GI term
	if n := len(events(parseOne(t, dpi.ServerToClient, serverStream()))); n != 11 {
		t.Fatalf("server events %d, want 11", n)
	}
}

// Without a direction or a session the stream cannot be attributed: the
// decoder must not guess, and fails closed with a FrameError at Base.
func TestUnattributedStreamFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		v      dpi.StreamView
		reason string
	}{
		{"direction unknown", dpi.StreamView{Session: testSession, Dir: dpi.DirUnknown, Base: 77, Bytes: clientStream()}, "direction unknown"},
		{"legacy flow-hash view", dpi.StreamView{Session: iecState().Key.Hash(), Base: 0, Bytes: clientStream()}, "direction unknown"},
		{"session unknown", dpi.StreamView{Dir: dpi.ClientToServer, Base: 77, Bytes: clientStream()}, "session unknown"},
	} {
		res, err := NewDecoder().ParseStream(iecState(), tc.v)
		var fe *dpi.FrameError
		if !errors.As(err, &fe) || fe.Offset != tc.v.Base || fe.Reason != tc.reason {
			t.Fatalf("%s: err = %v", tc.name, err)
		}
		if len(res.Frames) != 0 || res.Consumed != 0 {
			t.Fatalf("%s: parsed %d frames", tc.name, len(res.Frames))
		}
		a := fe.Event.Attributes
		if fe.Event.Kind != eventfields.KindMalformed || a[eventfields.KeyError] != tc.reason {
			t.Fatalf("%s: event %+v", tc.name, fe.Event)
		}
		for _, k := range []string{eventfields.KeyAPDUID, eventfields.KeySessionID, eventfields.KeyDirection} {
			if _, ok := a[k]; ok {
				t.Fatalf("%s: unattributed event carries %s", tc.name, k)
			}
		}
	}
}

func TestOnPacket(t *testing.T) {
	d := NewDecoder()
	st := iecState()
	if evs, err := d.OnPacket(st, nil); evs != nil || err != nil {
		t.Fatalf("nil packet: %v %v", evs, err)
	}
	tracked := &dpi.ParsedPacket{Proto: "tcp", Payload: clientStream(), HasOffset: true, Offset: 40, Session: testSession, Dir: dpi.ClientToServer}
	evs, err := d.OnPacket(st, tracked)
	if err != nil || len(evs) != 6 || evs[1].Attributes[eventfields.KeyAPDUID] != testSession+"/c/46" {
		t.Fatalf("tracked packet: %d events, %v", len(evs), err)
	}
	// A packet without session identity fails closed.
	evs, err = d.OnPacket(st, &dpi.ParsedPacket{Proto: "tcp", Payload: clientStream()})
	var fe *dpi.FrameError
	if !errors.As(err, &fe) || len(evs) != 1 || evs[0].Kind != eventfields.KindMalformed {
		t.Fatalf("untracked packet: %d events, %v", len(evs), err)
	}
}

// Several APDUs and objects per segment, delivered split at every byte:
// each APDU is decoded once, when it completes.
func TestSplitAtEveryByte(t *testing.T) {
	decodertest.CheckSplits(t, NewDecoder(), iecState(), view(dpi.ClientToServer, 0, clientStream()))
	decodertest.CheckSplits(t, NewDecoder(), iecState(), view(dpi.ServerToClient, 4096, serverStream()))
	withError := cat(serverStream()[:22], []byte{0x68, 0x04, 0x01, 0x00, 0x01, 0x00}, uFrame(testfrAct))
	decodertest.CheckSplits(t, NewDecoder(), iecState(), view(dpi.ServerToClient, 9, withError))
}

// Through the DPI manager on a session stream (HasOffset): absolute
// offsets, both directions independent, retransmissions emit nothing.
func TestManagerSessionStream(t *testing.T) {
	mgr := dpi.NewManager(NewDecoder())
	st := iecState()
	seg := func(dir dpi.StreamDir, off int64, b []byte) *dpi.ParsedPacket {
		return &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: Port, Payload: b, HasOffset: true, Offset: off, Session: testSession, Dir: dir}
	}
	c := clientStream()
	first := mgr.Inspect(st, seg(dpi.ClientToServer, 0, c[:20]))
	if first.Err != nil || !first.Framed || first.Proto != "iec104" || len(first.Frames) != 1 || !first.NeedMore {
		t.Fatalf("first: %+v", first)
	}
	again := mgr.Inspect(st, seg(dpi.ClientToServer, 0, c[:20]))
	if len(again.Events) != 0 {
		t.Fatalf("retransmission emitted %d events", len(again.Events))
	}
	rest := mgr.Inspect(st, seg(dpi.ClientToServer, 20, c[20:]))
	if rest.Err != nil || rest.NeedMore || len(rest.Frames) != 5 || rest.Frames[0].Start != 6 {
		t.Fatalf("rest: err %v frames %d", rest.Err, len(rest.Frames))
	}
	srv := mgr.Inspect(st, seg(dpi.ServerToClient, 0, uFrame(startdtCon)))
	if len(srv.Events) != 1 || srv.Events[0].Attributes[eventfields.KeyAPDUID] != testSession+"/s/0" {
		t.Fatalf("server direction: %+v", srv.Events)
	}
}

func TestRawHexIsTheAPDU(t *testing.T) {
	frame := iFrame(0, 0, asdu(3, vsqSQ|127, cotInrogen, 0, 1, cat(ioa(1), make([]byte, 127))...))
	if len(frame) != 2+4+6+3+127 {
		t.Fatalf("fixture length %d", len(frame))
	}
	evs := events(parseOne(t, dpi.ServerToClient, frame))
	if len(evs) != 127 {
		t.Fatalf("%d events", len(evs))
	}
	raw, _ := eventfields.String(evs[126].Attributes, eventfields.KeyRawHex)
	if len(raw) != 2*len(frame) {
		t.Fatalf("raw_hex %d hex chars, want %d", len(raw), 2*len(frame))
	}
	// A FrameError event's bytes stop at one maximal APDU.
	_, err := NewDecoder().ParseStream(iecState(), view(dpi.ClientToServer, 0, cat([]byte{0x00}, make([]byte, 600))))
	var fe *dpi.FrameError
	if !errors.As(err, &fe) || len(fe.Event.Attributes[eventfields.KeyRawHex].(string)) != 2*255 {
		t.Fatalf("FrameError raw_hex not capped at 255 bytes: %v", err)
	}
}
