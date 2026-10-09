// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"errors"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Wire rules of IEC 60870-5-104 clause 5 that make bytes unframeable.
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
		{"I reserved bit", []byte{0x68, 14, 0x00, 0x00, 0x01, 0x00}, "I-format control octet 3"},
		{"S octet 1 bits", []byte{0x68, 4, 0x05, 0x00, 0x00, 0x00}, "S-format control field"},
		{"S octet 2", []byte{0x68, 4, 0x01, 0x01, 0x00, 0x00}, "S-format control field"},
		{"S octet 3 bit 0", []byte{0x68, 4, 0x01, 0x00, 0x01, 0x00}, "S-format control field"},
		{"U two functions", []byte{0x68, 4, 0x47, 0, 0, 0}, "U-format"},
		{"U no function", []byte{0x68, 4, 0x03, 0, 0, 0}, "U-format"},
		{"U octet 2", []byte{0x68, 4, 0x07, 1, 0, 0}, "U-format"},
		{"U octet 4", []byte{0x68, 4, 0x43, 0, 0, 0x80}, "U-format"},
	}
	for _, tc := range cases {
		n, err := frameAPDU(tc.b)
		if err == nil || n != 0 || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: frameAPDU(% x) = %d, %v; want error %q", tc.name, tc.b, n, err, tc.want)
		}
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
