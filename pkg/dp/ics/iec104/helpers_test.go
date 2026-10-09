// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Synthetic APDU builders. Every byte layout follows IEC 60870-5-104 clause
// 5 (APCI) and IEC 60870-5-101 7.2/7.3 (ASDU) with the IEC 104 field widths
// (COT 2, CA 2, IOA 3 octets). Nothing here is captured traffic.

const testSession = "run0-1"

func iecState() *flow.State {
	return flow.NewState(flow.Key{Proto: 6, SrcPort: 40000, DstPort: Port}, time.Now())
}

// iFrame wraps an ASDU in an I-format APDU with N(S)=ns and N(R)=nr.
func iFrame(ns, nr uint16, asdu []byte) []byte {
	b := []byte{startOctet, byte(4 + len(asdu))}
	b = binary.LittleEndian.AppendUint16(b, ns<<1)
	b = binary.LittleEndian.AppendUint16(b, nr<<1)
	return append(b, asdu...)
}

// sFrame is an S-format APDU acknowledging up to N(R)=nr.
func sFrame(nr uint16) []byte {
	b := []byte{startOctet, 4, 0x01, 0x00}
	return binary.LittleEndian.AppendUint16(b, nr<<1)
}

// uFrame is a U-format APDU with control octet 1 = fn.
func uFrame(fn byte) []byte { return []byte{startOctet, 4, fn, 0, 0, 0} }

const (
	startdtAct = 0x07
	startdtCon = 0x0B
	stopdtAct  = 0x13
	testfrAct  = 0x43
	testfrCon  = 0x83
)

// asdu builds Type ID, VSQ, COT (cause | P/N | T, originator), CA and body.
func asdu(typeID, vsq, cot, originator uint8, ca uint16, body ...byte) []byte {
	b := []byte{typeID, vsq, cot, originator}
	b = binary.LittleEndian.AppendUint16(b, ca)
	return append(b, body...)
}

func ioa(n uint32) []byte { return []byte{byte(n), byte(n >> 8), byte(n >> 16)} }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// cp56 encodes CP56Time2a fields (IEC 60870-5-101 7.2.6.18) without flags.
func cp56(year, month, day, hour, minute, ms int) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(ms))
	return append(b, byte(minute), byte(hour), byte(day), byte(month), byte(year))
}

func f32(v float32) []byte {
	return binary.LittleEndian.AppendUint32(nil, math.Float32bits(v))
}

// view is a client or server stream view starting at base.
func view(dir dpi.StreamDir, base int64, b []byte) dpi.StreamView {
	return dpi.StreamView{Session: testSession, Dir: dir, Base: base, Bytes: b}
}

// parseOne parses a stream that must frame without error.
func parseOne(t *testing.T, dir dpi.StreamDir, b []byte) dpi.StreamResult {
	t.Helper()
	res, err := NewDecoder().ParseStream(iecState(), view(dir, 0, b))
	if err != nil {
		t.Fatalf("ParseStream(% x): %v", b, err)
	}
	return res
}

// events flattens the events of every frame.
func events(res dpi.StreamResult) []dpi.Event {
	var out []dpi.Event
	for _, f := range res.Frames {
		out = append(out, f.Events...)
	}
	return out
}
