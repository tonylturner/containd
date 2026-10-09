// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// appFrame builds a complete link frame carrying one application fragment
// with function code fc and extra object bytes.
func appFrame(seq, fc byte, objects ...byte) []byte {
	userData := append([]byte{0xC0 | seq, 0xC0 | seq, fc}, objects...)
	return buildTestFrame(byte(5+len(userData)), 0xC4, 0x0001, 0x0002, userData)
}

func dnpSeg(seq uint32, payload []byte) *dpi.ParsedPacket {
	return &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: 20000, Payload: payload, TCPSeq: seq, HasTCPSeq: true}
}

func feedStream(t *testing.T, mgr *dpi.Manager, st *flow.State, pkts ...*dpi.ParsedPacket) []dpi.Event {
	t.Helper()
	var out []dpi.Event
	for _, p := range pkts {
		evs, err := mgr.OnPacket(st, p)
		if err != nil {
			t.Fatalf("OnPacket: %v", err)
		}
		out = append(out, evs...)
	}
	return out
}

func assertDNP3Frames(t *testing.T, evs []dpi.Event, want ...[]byte) {
	t.Helper()
	if len(evs) != len(want) {
		t.Fatalf("got %d events, want %d: %+v", len(evs), len(want), evs)
	}
	for i, w := range want {
		if got := evs[i].Attributes["raw_hex"]; got != hex.EncodeToString(w) {
			t.Fatalf("event %d raw_hex = %v, want %x", i, got, w)
		}
	}
}

func newDNP3Stream() (*dpi.Manager, *flow.State) {
	return dpi.NewManager(NewDecoder()), flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 40000, 20000), time.Now())
}

func TestStreamPersistentReadOperateRead(t *testing.T) {
	mgr, st := newDNP3Stream()
	read1 := appFrame(1, FuncRead, 0x3C, 0x02, 0x06)
	// Direct operate with a CROB object: 20 bytes of user data, so the
	// frame spans two CRC blocks.
	operate := appFrame(2, FuncDirectOperate, 0x0C, 0x01, 0x28, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00)
	read2 := appFrame(3, FuncRead, 0x3C, 0x02, 0x06)

	var seq uint32 = 7000
	var pkts []*dpi.ParsedPacket
	for _, f := range [][]byte{read1, operate, read2} {
		pkts = append(pkts, dnpSeg(seq, f))
		seq += uint32(len(f))
	}
	evs := feedStream(t, mgr, st, pkts...)
	assertDNP3Frames(t, evs, read1, operate, read2)
	if evs[1].Attributes["function_code"] != uint8(FuncDirectOperate) || evs[1].Attributes["is_control"] != true {
		t.Fatalf("operate event = %+v", evs[1].Attributes)
	}
}

func TestStreamDNP3SplitCoalescedAndRetransmitted(t *testing.T) {
	mgr, st := newDNP3Stream()
	f1 := appFrame(1, FuncRead, 0x3C, 0x02, 0x06)
	f2 := appFrame(2, FuncWrite, 0x50, 0x01, 0x00, 0x07, 0x07, 0x00)
	f3 := appFrame(3, FuncRead, 0x3C, 0x03, 0x06)
	wire := append(append(append([]byte(nil), f1...), f2...), f3...)
	cut1, cut2 := 6, len(f1)+len(f2)+4

	evs := feedStream(t, mgr, st,
		dnpSeg(0, wire[:cut1]),
		dnpSeg(uint32(cut1), wire[cut1:cut2]),
		dnpSeg(uint32(cut1), wire[cut1:cut2]), // retransmission
		dnpSeg(uint32(cut2), wire[cut2:]),
		dnpSeg(0, wire[:cut1]), // late retransmission
	)
	assertDNP3Frames(t, evs, f1, f2, f3)
}

func TestStreamDNP3SequenceWrap(t *testing.T) {
	mgr, st := newDNP3Stream()
	f1 := appFrame(1, FuncRead, 0x3C, 0x02, 0x06)
	f2 := appFrame(2, FuncWrite, 0x50, 0x01, 0x00, 0x07, 0x07, 0x00)
	start := uint32(0xFFFFFFFC)
	evs := feedStream(t, mgr, st, dnpSeg(start, f1), dnpSeg(start+uint32(len(f1)), f2), dnpSeg(start, f1))
	assertDNP3Frames(t, evs, f1, f2)
}

func TestStreamDNP3BadFrameDiscardsBuffer(t *testing.T) {
	good := appFrame(2, FuncWrite, 0x50, 0x01, 0x00, 0x07, 0x07, 0x00)

	badStart := []byte{0x05, 0x65, 0x0A, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00}
	badCRC := appFrame(1, FuncRead, 0x3C, 0x02, 0x06)
	badCRC[8] ^= 0xFF
	for name, bad := range map[string][]byte{"start": badStart, "crc": badCRC[:12]} {
		t.Run(name, func(t *testing.T) {
			mgr, st := newDNP3Stream()
			evs := feedStream(t, mgr, st, dnpSeg(0, bad), dnpSeg(uint32(len(bad)), good))
			assertDNP3Frames(t, evs, good)
		})
	}
}

func TestStreamDNP3EventShapeMatchesSingleFrame(t *testing.T) {
	mgr, st := newDNP3Stream()
	f := appFrame(1, FuncRead, 0x3C, 0x02, 0x06)
	evs := feedStream(t, mgr, st, dnpSeg(0, f))
	if len(evs) != 1 || evs[0].Proto != "dnp3" || evs[0].Kind != "request" || evs[0].FlowID != st.Key.Hash() {
		t.Fatalf("unexpected events: %+v", evs)
	}
	want := map[string]any{
		"function_code":       uint8(FuncRead),
		"function_name":       FunctionCodeName(FuncRead),
		"is_write":            false,
		"is_control":          false,
		"source_address":      uint16(2),
		"destination_address": uint16(1),
		"object_groups":       "60",
		"qualifier":           uint8(0x06),
		"object_count":        uint16(0),
		"raw_hex":             hex.EncodeToString(f),
	}
	if !reflect.DeepEqual(evs[0].Attributes, want) {
		t.Fatalf("attributes = %#v, want %#v", evs[0].Attributes, want)
	}
}
