// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Wire rules of IEC 60870-5-104 clause 5 that make bytes unframeable: only
// the start octet and the length octet bound an APDU.
func TestFrameAPDUErrors(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want string
	}{
		{"start octet", []byte{0x69}, "start octet 0x69"},
		{"length 3", []byte{0x68, 3}, "APDU length 3"},
		{"length 254", []byte{0x68, 254}, "APDU length 254"},
		{"length 0", []byte{0x68, 0}, "APDU length 0"},
	}
	for _, tc := range cases {
		n, err := frameAPDU(tc.b)
		if err == nil || n != 0 || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: frameAPDU(% x) = %d, %v; want error %q", tc.name, tc.b, n, err, tc.want)
		}
	}
}

// Reserved control bits never lose the frame boundary: the APDU frames, its
// readable fields are decoded and the event carries the finding. A U-format
// octet that is not exactly one function leaves u_function absent.
func TestControlFieldFindings(t *testing.T) {
	cases := []struct {
		name     string
		b        []byte
		kind     string
		findings []string
		attrs    objWant
		absent   []string
	}{
		{"I reserved bit", iFrame(1, 2, asdu(100, 1, cotAct, 0, 1, cat(ioa(0), []byte{20})...)), eventfields.KindRequest,
			[]string{FindingReservedBits}, objWant{eventfields.KeySendSequence: uint16(1), eventfields.KeyReceiveSequence: uint16(2), eventfields.KeyTypeID: uint8(100)}, nil},
		{"S octet 1 bits", []byte{0x68, 4, 0x05, 0x00, 0x04, 0x00}, eventfields.KindAPCI,
			[]string{FindingReservedBits}, objWant{eventfields.KeyAPCIType: "S", eventfields.KeyReceiveSequence: uint16(2)}, nil},
		{"S octet 2", []byte{0x68, 4, 0x01, 0x01, 0x04, 0x00}, eventfields.KindAPCI,
			[]string{FindingReservedBits}, objWant{eventfields.KeyAPCIType: "S", eventfields.KeyReceiveSequence: uint16(2)}, nil},
		{"S octet 3 bit 0", []byte{0x68, 4, 0x01, 0x00, 0x05, 0x00}, eventfields.KindAPCI,
			[]string{FindingReservedBits}, objWant{eventfields.KeyAPCIType: "S", eventfields.KeyReceiveSequence: uint16(2)}, nil},
		{"U two functions", []byte{0x68, 4, 0x47, 0, 0, 0}, eventfields.KindAPCI,
			[]string{FindingUFunction}, objWant{eventfields.KeyAPCIType: "U"}, []string{eventfields.KeyUFunction}},
		{"U no function", []byte{0x68, 4, 0x03, 0, 0, 0}, eventfields.KindAPCI,
			[]string{FindingUFunction}, objWant{eventfields.KeyAPCIType: "U"}, []string{eventfields.KeyUFunction}},
		{"U octet 2", []byte{0x68, 4, 0x07, 1, 0, 0}, eventfields.KindAPCI,
			[]string{FindingReservedBits}, objWant{eventfields.KeyAPCIType: "U", eventfields.KeyUFunction: "startdt_act"}, nil},
		{"U octet 4", []byte{0x68, 4, 0x43, 0, 0, 0x80}, eventfields.KindAPCI,
			[]string{FindingReservedBits}, objWant{eventfields.KeyAPCIType: "U", eventfields.KeyUFunction: "testfr_act"}, nil},
		{"U no function and reserved octets", []byte{0x68, 4, 0x0f, 0, 1, 0}, eventfields.KindAPCI,
			[]string{FindingReservedBits, FindingUFunction}, objWant{eventfields.KeyAPCIType: "U"}, []string{eventfields.KeyUFunction}},
		{"S reserved bit and wrong length", []byte{0x68, 5, 0x05, 0x00, 0x04, 0x00, 0xAA}, eventfields.KindMalformed,
			[]string{FindingAPCILength, FindingReservedBits}, objWant{eventfields.KeyAPCIType: "S", eventfields.KeyReceiveSequence: uint16(2)}, nil},
	}
	for _, tc := range cases {
		frame := append([]byte(nil), tc.b...)
		if tc.name == "I reserved bit" {
			frame[4] |= 0x01
		}
		evs := events(parseOne(t, cli, frame))
		if len(evs) != 1 || evs[0].Kind != tc.kind {
			t.Errorf("%s: %d events, kind %s, want one %s", tc.name, len(evs), evs[0].Kind, tc.kind)
			continue
		}
		a := evs[0].Attributes
		codes, _ := eventfields.Strings(a, eventfields.KeyConformance)
		if !reflect.DeepEqual(codes, tc.findings) {
			t.Errorf("%s: conformance %v, want %v", tc.name, codes, tc.findings)
		}
		if _, hasErr := a[eventfields.KeyError]; hasErr != (tc.kind == eventfields.KindMalformed) {
			t.Errorf("%s: error attribute present %v on %s", tc.name, hasErr, tc.kind)
		}
		if SafeRead(a) {
			t.Errorf("%s: SafeRead accepted nonconformant content", tc.name)
		}
		checkAttrs(t, tc.name, a, tc.attrs, tc.absent...)
	}
	// Reserved bits do not stop the stream: the next APDU parses.
	stream := cat([]byte{0x68, 4, 0x01, 0x00, 0x05, 0x00}, uFrame(testfrAct))
	if evs := events(parseOne(t, cli, stream)); len(evs) != 2 || evs[1].Kind != eventfields.KindAPCI {
		t.Fatalf("stream after a reserved-bit APDU: %+v", evs)
	}
}

// Incomplete APDUs need more bytes; framing never looks past the length.
func TestFrameAPDUNeedsMore(t *testing.T) {
	full := iFrame(1, 2, asdu(100, 0x01, 6, 0, 1, cat(ioa(0), []byte{20})...))
	for cut := 0; cut < len(full); cut++ {
		if n, err := frameAPDU(full[:cut]); n != 0 || err != nil {
			t.Fatalf("cut %d: %d, %v", cut, n, err)
		}
	}
	if n, err := frameAPDU(cat(full, []byte{0xFF})); n != len(full) || err != nil {
		t.Fatalf("complete APDU with trailing byte: %d, %v", n, err)
	}
}

func TestDecodeAPCISequences(t *testing.T) {
	// N(S) and N(R) are 15 bits; 32767 is the largest.
	a := decodeAPCI(iFrame(32767, 12345, asdu(100, 1, 6, 0, 1, cat(ioa(0), []byte{20})...)))
	if a.format != "I" || a.sendSeq != 32767 || a.recvSeq != 12345 {
		t.Fatalf("I: %+v", a)
	}
	// Literal octets: N(S)=1 is 0x02 0x00, N(R)=2 is 0x04 0x00.
	if got := iFrame(1, 2, nil)[2:6]; string(got) != string([]byte{0x02, 0x00, 0x04, 0x00}) {
		t.Fatalf("I control octets % x", got)
	}
	if a := decodeAPCI(sFrame(300)); a.format != "S" || a.recvSeq != 300 {
		t.Fatalf("S: %+v", a)
	}
	for fn, name := range uFunctions {
		if a := decodeAPCI(uFrame(fn)); a.format != "U" || a.uFunction != name {
			t.Fatalf("U 0x%02x: %+v", fn, a)
		}
	}
}

func TestSAndUFrameEvents(t *testing.T) {
	stream := cat(uFrame(startdtAct), sFrame(7), uFrame(testfrCon), uFrame(stopdtAct))
	evs := events(parseOne(t, dpi.ServerToClient, stream))
	if len(evs) != 4 {
		t.Fatalf("%d events", len(evs))
	}
	wantU := []string{"startdt_act", "", "testfr_con", "stopdt_act"}
	for i, ev := range evs {
		a := ev.Attributes
		if ev.Kind != eventfields.KindAPCI || ev.Proto != "iec104" || a[eventfields.KeyClass] != ClassSystem ||
			a[eventfields.KeyDirection] != DirectionResponse || a[eventfields.KeyIsWrite] != false {
			t.Fatalf("event %d: %s %+v", i, ev.Kind, a)
		}
		if _, ok := a[eventfields.KeyError]; ok {
			t.Fatalf("event %d has an error: %+v", i, a)
		}
		if wantU[i] == "" {
			if a[eventfields.KeyAPCIType] != "S" || a[eventfields.KeyReceiveSequence] != uint16(7) {
				t.Fatalf("S event %+v", a)
			}
			if _, ok := a[eventfields.KeySendSequence]; ok {
				t.Fatal("S event carries send_sequence")
			}
			continue
		}
		if a[eventfields.KeyAPCIType] != "U" || a[eventfields.KeyUFunction] != wantU[i] {
			t.Fatalf("U event %+v", a)
		}
		for _, k := range []string{eventfields.KeySendSequence, eventfields.KeyReceiveSequence, eventfields.KeyTypeID, eventfields.KeyCA} {
			if _, ok := a[k]; ok {
				t.Fatalf("U event carries %s", k)
			}
		}
	}
}

// S- and U-format APDUs must have length 4 (clause 5); a longer one still
// frames, so it is a malformed event and parsing continues.
func TestSAndUFrameWrongLength(t *testing.T) {
	longS := []byte{0x68, 6, 0x01, 0x00, 0x02, 0x00, 0xAA, 0xBB}
	longU := []byte{0x68, 5, 0x43, 0, 0, 0, 0xCC}
	res := parseOne(t, dpi.ClientToServer, cat(longS, longU, uFrame(testfrAct)))
	evs := events(res)
	if len(res.Frames) != 3 || len(evs) != 3 {
		t.Fatalf("%d frames, %d events", len(res.Frames), len(evs))
	}
	for i, want := range []string{"S-format APDU length 6", "U-format APDU length 5"} {
		if evs[i].Kind != eventfields.KindMalformed || !strings.Contains(evs[i].Attributes[eventfields.KeyError].(string), want) {
			t.Fatalf("event %d: %s %+v", i, evs[i].Kind, evs[i].Attributes)
		}
		if codes, _ := eventfields.Strings(evs[i].Attributes, eventfields.KeyConformance); !reflect.DeepEqual(codes, []string{FindingAPCILength}) {
			t.Fatalf("event %d: conformance %v", i, codes)
		}
	}
	if evs[2].Kind != eventfields.KindAPCI {
		t.Fatalf("parsing did not continue: %s", evs[2].Kind)
	}
}

// An unframeable APDU after good ones: the good frames are returned, the
// FrameError sits at the bad APDU's absolute offset and nothing after it is
// parsed (no scan-forward resync).
func TestFrameErrorStopsParsing(t *testing.T) {
	good := uFrame(testfrAct)
	stream := cat(good, []byte{0x68, 0x02}, good)
	res, err := NewDecoder().ParseStream(iecState(), view(dpi.ClientToServer, 500, stream))
	var fe *dpi.FrameError
	if !errors.As(err, &fe) || fe.Offset != 506 || !strings.Contains(fe.Reason, "APDU length 2") {
		t.Fatalf("err = %v", err)
	}
	if len(res.Frames) != 1 || res.Consumed != 6 || res.NeedMore {
		t.Fatalf("frames %d consumed %d needMore %v", len(res.Frames), res.Consumed, res.NeedMore)
	}
	a := fe.Event.Attributes
	if fe.Event.Kind != eventfields.KindMalformed || a[eventfields.KeyAPDUID] != testSession+"/c/506" ||
		a[eventfields.KeySessionID] != testSession || a[eventfields.KeyDirection] != DirectionRequest ||
		a[eventfields.KeyRawHex] != "6802680443000000" || a[eventfields.KeyError] != fe.Reason {
		t.Fatalf("FrameError event %+v", a)
	}
}
