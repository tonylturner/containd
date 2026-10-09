// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

const (
	cotSpont     = 3
	cotInit      = 4
	cotRequest   = 5
	cotAct       = 6
	cotActCon    = 7
	cotDeact     = 8
	cotActTerm   = 10
	cotUnknownCA = 46
	cotInrogen   = 20
	bitNegative  = 0x40
	bitTest      = 0x80
	vsqSQ        = 0x80
)

var (
	cli = dpi.ClientToServer
	srv = dpi.ServerToClient
	// 2026-11-07T09:15:02.345 as CP56Time2a.
	courseTime = cp56(26, 11, 7, 9, 15, 2345)
)

type objWant map[string]any

// checkAttrs fails unless every wanted key has exactly that value and Go
// type, and no absent key is present.
func checkAttrs(t *testing.T, label string, got map[string]any, want objWant, absent ...string) {
	t.Helper()
	for k, w := range want {
		if g, ok := got[k]; !ok || !reflect.DeepEqual(g, w) {
			t.Errorf("%s: %s = %#v, want %#v", label, k, g, w)
		}
	}
	for _, k := range absent {
		if v, ok := got[k]; ok {
			t.Errorf("%s: unexpected %s = %#v", label, k, v)
		}
	}
}

// One table row per Type ID with a B descriptor (spec §7.2): element sizes,
// little-endian values, flag bits, select placement and timestamps.
func TestDescriptorTable(t *testing.T) {
	noSelect := []string{eventfields.KeySelect}
	noTime := []string{eventfields.KeySourceTime, eventfields.KeyTimeValid, eventfields.KeyTimeSummer}
	timeWant := objWant{eventfields.KeySourceTime: "2026-11-07T09:15:02.345", eventfields.KeyTimeValid: true, eventfields.KeyTimeSummer: false}
	with := func(a, b objWant) objWant {
		out := objWant{}
		for k, v := range a {
			out[k] = v
		}
		for k, v := range b {
			out[k] = v
		}
		return out
	}
	cases := []struct {
		name    string
		dir     dpi.StreamDir
		asdu    []byte
		class   string
		isWrite bool
		want    objWant
		absent  []string
	}{
		{"3 M_DP_NA_1 DIQ", srv, asdu(3, 1, cotSpont, 0, 1, cat(ioa(0x123456), []byte{0x82})...), ClassMonitor, false,
			objWant{eventfields.KeyIOA: uint32(0x123456), eventfields.KeyValue: uint8(2), eventfields.KeyQuality: uint8(0x80)},
			append(append([]string{eventfields.KeyQualifier}, noSelect...), noTime...)},
		{"13 M_ME_NC_1 float+QDS", srv, asdu(13, 1, cotInrogen, 0, 1, cat(ioa(2001), f32(-12.5), []byte{0x01})...), ClassMonitor, false,
			objWant{eventfields.KeyValue: float32(-12.5), eventfields.KeyQuality: uint8(0x01)}, append(noSelect, noTime...)},
		{"31 M_DP_TB_1 DIQ+CP56", srv, asdu(31, 1, cotSpont, 0, 1, cat(ioa(3001), []byte{0x01}, courseTime)...), ClassMonitor, false,
			with(timeWant, objWant{eventfields.KeyValue: uint8(1), eventfields.KeyQuality: uint8(0)}), noSelect},
		{"45 C_SC_NA_1 SCO select", cli, asdu(45, 1, cotAct, 0, 1, cat(ioa(5001), []byte{0x85})...), ClassControl, true,
			objWant{eventfields.KeyValue: uint8(1), eventfields.KeySelect: true, eventfields.KeyQualifier: uint8(1)}, noTime},
		{"46 C_DC_NA_1 DCO execute", cli, asdu(46, 1, cotAct, 3, 1, cat(ioa(2001), []byte{0x02})...), ClassControl, true,
			objWant{eventfields.KeyValue: uint8(2), eventfields.KeySelect: false, eventfields.KeyQualifier: uint8(0), eventfields.KeyOriginator: uint8(3)}, noTime},
		{"47 C_RC_NA_1 RCO", cli, asdu(47, 1, cotAct, 0, 1, cat(ioa(6001), []byte{0x8D})...), ClassControl, true,
			objWant{eventfields.KeyValue: uint8(1), eventfields.KeySelect: true, eventfields.KeyQualifier: uint8(3)}, noTime},
		{"48 C_SE_NA_1 NVA+QOS", cli, asdu(48, 1, cotAct, 0, 1, cat(ioa(7001), []byte{0x00, 0xC0, 0x80})...), ClassControl, true,
			objWant{eventfields.KeyValue: int16(-16384), eventfields.KeySelect: true, eventfields.KeyQualifier: uint8(0)}, noTime},
		{"49 C_SE_NB_1 SVA+QOS", cli, asdu(49, 1, cotAct, 0, 1, cat(ioa(7002), []byte{0xD2, 0x04, 0x05})...), ClassControl, true,
			objWant{eventfields.KeyValue: int16(1234), eventfields.KeySelect: false, eventfields.KeyQualifier: uint8(5)}, noTime},
		{"50 C_SE_NC_1 float+QOS", cli, asdu(50, 1, cotAct, 0, 1, cat(ioa(7003), f32(49.5), []byte{0x7F})...), ClassControl, true,
			objWant{eventfields.KeyValue: float32(49.5), eventfields.KeySelect: false, eventfields.KeyQualifier: uint8(127)}, noTime},
		{"51 C_BO_NA_1 BSI", cli, asdu(51, 1, cotAct, 0, 1, cat(ioa(8001), []byte{0xEF, 0xBE, 0xAD, 0xDE})...), ClassControl, true,
			objWant{eventfields.KeyValue: uint32(0xDEADBEEF)}, append(append([]string{eventfields.KeyQualifier}, noSelect...), noTime...)},
		{"58 C_SC_TA_1 SCO+CP56", cli, asdu(58, 1, cotAct, 0, 1, cat(ioa(5002), []byte{0x80}, courseTime)...), ClassControl, true,
			with(timeWant, objWant{eventfields.KeyValue: uint8(0), eventfields.KeySelect: true}), nil},
		{"59 C_DC_TA_1 DCO+CP56", cli, asdu(59, 1, cotAct, 0, 1, cat(ioa(2002), []byte{0x01}, courseTime)...), ClassControl, true,
			with(timeWant, objWant{eventfields.KeyValue: uint8(1), eventfields.KeySelect: false}), nil},
		{"60 C_RC_TA_1 RCO+CP56", cli, asdu(60, 1, cotAct, 0, 1, cat(ioa(6002), []byte{0x02}, courseTime)...), ClassControl, true,
			with(timeWant, objWant{eventfields.KeyValue: uint8(2)}), nil},
		{"61 C_SE_TA_1 NVA+QOS+CP56", cli, asdu(61, 1, cotAct, 0, 1, cat(ioa(7004), []byte{0xFF, 0x7F, 0x00}, courseTime)...), ClassControl, true,
			with(timeWant, objWant{eventfields.KeyValue: int16(32767), eventfields.KeySelect: false}), nil},
		{"62 C_SE_TB_1 SVA+QOS+CP56", cli, asdu(62, 1, cotAct, 0, 1, cat(ioa(7005), []byte{0x00, 0x80, 0x81}, courseTime)...), ClassControl, true,
			with(timeWant, objWant{eventfields.KeyValue: int16(-32768), eventfields.KeySelect: true, eventfields.KeyQualifier: uint8(1)}), nil},
		{"63 C_SE_TC_1 float+QOS+CP56", cli, asdu(63, 1, cotAct, 0, 1, cat(ioa(7006), f32(0.25), []byte{0x00}, courseTime)...), ClassControl, true,
			with(timeWant, objWant{eventfields.KeyValue: float32(0.25)}), nil},
		{"64 C_BO_TA_1 BSI+CP56", cli, asdu(64, 1, cotAct, 0, 1, cat(ioa(8002), []byte{1, 0, 0, 0}, courseTime)...), ClassControl, true,
			with(timeWant, objWant{eventfields.KeyValue: uint32(1)}), append([]string{eventfields.KeyQualifier}, noSelect...)},
		{"70 M_EI_NA_1 COI", srv, asdu(70, 1, cotInit, 0, 1, cat(ioa(0), []byte{0x02})...), ClassSystem, false,
			objWant{eventfields.KeyIOA: uint32(0), eventfields.KeyQualifier: uint8(2)}, append(append([]string{eventfields.KeyValue}, noSelect...), noTime...)},
		{"100 C_IC_NA_1 QOI", cli, asdu(100, 1, cotAct, 0, 1, cat(ioa(0), []byte{20})...), ClassSystem, false,
			objWant{eventfields.KeyIOA: uint32(0), eventfields.KeyQualifier: uint8(20)}, append([]string{eventfields.KeyValue}, noSelect...)},
		{"101 C_CI_NA_1 QCC", cli, asdu(101, 1, cotAct, 0, 1, cat(ioa(0), []byte{0x45})...), ClassSystem, true,
			objWant{eventfields.KeyQualifier: uint8(0x45)}, []string{eventfields.KeyValue}},
		{"102 C_RD_NA_1 read", cli, asdu(102, 1, cotRequest, 0, 1, ioa(4001)...), ClassSystem, false,
			objWant{eventfields.KeyIOA: uint32(4001)}, append([]string{eventfields.KeyValue, eventfields.KeyQualifier}, noSelect...)},
		{"103 C_CS_NA_1 clock sync", cli, asdu(103, 1, cotAct, 0, 1, cat(ioa(0), courseTime)...), ClassSystem, true,
			timeWant, []string{eventfields.KeyValue, eventfields.KeyQualifier}},
		{"105 C_RP_NA_1 QRP", cli, asdu(105, 1, cotAct, 0, 1, cat(ioa(0), []byte{1})...), ClassSystem, true,
			objWant{eventfields.KeyQualifier: uint8(1)}, []string{eventfields.KeyValue}},
		{"107 C_TS_TA_1 TSC+CP56", cli, asdu(107, 1, cotAct, 0, 1, cat(ioa(0), []byte{0x34, 0x12}, courseTime)...), ClassSystem, false,
			timeWant, []string{eventfields.KeyValue, eventfields.KeyQualifier}},
	}
	if len(cases) != len(descriptors) {
		t.Fatalf("%d cases for %d descriptors", len(cases), len(descriptors))
	}
	for _, tc := range cases {
		evs := events(parseOne(t, tc.dir, iFrame(3, 4, tc.asdu)))
		if len(evs) != 1 {
			t.Fatalf("%s: %d events", tc.name, len(evs))
		}
		kind := eventfields.KindResponse
		if tc.dir == cli {
			kind = eventfields.KindRequest
		}
		if evs[0].Kind != kind {
			t.Errorf("%s: kind %s (%v)", tc.name, evs[0].Kind, evs[0].Attributes[eventfields.KeyError])
		}
		want := with(tc.want, objWant{
			eventfields.KeyClass:       tc.class,
			eventfields.KeyIsWrite:     tc.isWrite,
			eventfields.KeyTypeID:      tc.asdu[0],
			eventfields.KeyObjectIndex: uint8(0),
		})
		checkAttrs(t, tc.name, evs[0].Attributes, want, append(tc.absent, eventfields.KeyValueInvalid, eventfields.KeyError, eventfields.KeyFunctionCode, "address")...)
	}
}

func TestHeaderAttributes(t *testing.T) {
	// Type 46 confirmation: P/N and T set, originator 9, CA 0x1234.
	frame := iFrame(32767, 1, asdu(46, 1, cotActCon|bitNegative|bitTest, 9, 0x1234, cat(ioa(2001), []byte{0x81})...))
	ev := events(parseOne(t, srv, frame))[0]
	checkAttrs(t, "header", ev.Attributes, objWant{
		eventfields.KeyAPCIType:        "I",
		eventfields.KeySendSequence:    uint16(32767),
		eventfields.KeyReceiveSequence: uint16(1),
		eventfields.KeyTypeID:          uint8(46),
		eventfields.KeyVSQ:             uint8(1),
		eventfields.KeyObjectCount:     uint8(1),
		eventfields.KeySQ:              false,
		eventfields.KeyCause:           uint8(cotActCon),
		eventfields.KeyCOTNegative:     true,
		eventfields.KeyCOTTest:         true,
		eventfields.KeyOriginator:      uint8(9),
		eventfields.KeyCA:              uint16(0x1234),
		eventfields.KeyClass:           ClassControl,
		eventfields.KeyDirection:       DirectionResponse,
		eventfields.KeyIsWrite:         false,
		eventfields.KeyRawHex:          "680efeff02002e01c7093412d1070081",
	}, eventfields.KeyUFunction)
	if ev.Kind != eventfields.KindResponse {
		t.Fatalf("type 46 confirmation is %s, want response", ev.Kind)
	}
}

// SQ=1: one base IOA, consecutive IOAs; SQ=0: one IOA per object. Objects of
// one APDU share its identity and get their own index.
func TestMultipleObjects(t *testing.T) {
	sq := iFrame(0, 0, asdu(13, vsqSQ|3, cotInrogen, 0, 1, cat(ioa(65535), f32(1), []byte{0}, f32(2), []byte{0}, f32(3), []byte{0x80})...))
	perIOA := iFrame(1, 0, asdu(31, 2, cotSpont, 0, 1, cat(ioa(16777215), []byte{0x01}, courseTime, ioa(0), []byte{0x02}, courseTime)...))
	res := parseOne(t, srv, cat(sq, perIOA))
	if len(res.Frames) != 2 || len(res.Frames[0].Events) != 3 || len(res.Frames[1].Events) != 2 {
		t.Fatalf("frames %d", len(res.Frames))
	}
	wantIOA := [][]uint32{{65535, 65536, 65537}, {16777215, 0}}
	for fi, f := range res.Frames {
		apduID := f.Events[0].Attributes[eventfields.KeyAPDUID]
		for oi, ev := range f.Events {
			checkAttrs(t, "object", ev.Attributes, objWant{
				eventfields.KeyIOA:         wantIOA[fi][oi],
				eventfields.KeyObjectIndex: uint8(oi),
				eventfields.KeyAPDUID:      apduID,
			})
		}
	}
	if got := res.Frames[0].Events[2].Attributes[eventfields.KeyQuality]; got != uint8(0x80) {
		t.Fatalf("third object quality %#v", got)
	}
}

func TestMalformedAndProfile(t *testing.T) {
	cases := []struct {
		name  string
		dir   dpi.StreamDir
		frame []byte
		kind  string
		err   string
	}{
		{"I-format without ASDU", cli, iFrame(0, 0, nil), eventfields.KindMalformed, "shorter than its 6-octet header"},
		{"ASDU header cut", cli, iFrame(0, 0, []byte{100, 1, 6, 0, 1}), eventfields.KindMalformed, "shorter than its 6-octet header"},
		{"zero objects", cli, iFrame(0, 0, asdu(100, 0, cotAct, 0, 1)), eventfields.KindMalformed, "zero information objects"},
		{"extra byte", cli, iFrame(0, 0, asdu(100, 1, cotAct, 0, 1, cat(ioa(0), []byte{20, 0})...)), eventfields.KindMalformed, "ASDU body is 5 octets, want 4"},
		{"missing byte", srv, iFrame(0, 0, asdu(13, 1, cotSpont, 0, 1, cat(ioa(1), f32(1))...)), eventfields.KindMalformed, "ASDU body is 7 octets, want 8"},
		{"SQ=1 IOA overflow", srv, iFrame(0, 0, asdu(3, vsqSQ|2, cotSpont, 0, 1, cat(ioa(16777215), []byte{1, 1})...)), eventfields.KindMalformed, "overflows 24 bits"},
		{"SCO reserved bit", cli, iFrame(0, 0, asdu(45, 1, cotAct, 0, 1, cat(ioa(1), []byte{0x03})...)), eventfields.KindMalformed, "SCO reserved bit 1"},
		{"DCO state 0", cli, iFrame(0, 0, asdu(46, 1, cotAct, 0, 1, cat(ioa(1), []byte{0x80})...)), eventfields.KindMalformed, "command state 0"},
		{"DCO state 3", cli, iFrame(0, 0, asdu(46, 1, cotAct, 0, 1, cat(ioa(1), []byte{0x03})...)), eventfields.KindMalformed, "command state 3"},
		{"RCO state 0", cli, iFrame(0, 0, asdu(60, 1, cotAct, 0, 1, cat(ioa(1), []byte{0x00}, courseTime)...)), eventfields.KindMalformed, "command state 0"},
		{"bad CP56", srv, iFrame(0, 0, asdu(31, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1}, cp56(25, 2, 29, 0, 0, 0))...)), eventfields.KindMalformed, "CP56Time2a day 29"},
		{"profile: SQ=1 on 31", srv, iFrame(0, 0, asdu(31, vsqSQ|1, cotSpont, 0, 1, cat(ioa(1), []byte{1}, courseTime)...)), eventfields.KindMalformed, "profile: SQ=1 is not accepted for type 31"},
		{"profile: SQ=1 on 46", cli, iFrame(0, 0, asdu(46, vsqSQ|1, cotAct, 0, 1, cat(ioa(1), []byte{1})...)), eventfields.KindMalformed, "profile: type 46 needs SQ=0 and one object"},
		{"profile: two commands", cli, iFrame(0, 0, asdu(46, 2, cotAct, 0, 1, cat(ioa(1), []byte{1}, ioa(2), []byte{1})...)), eventfields.KindMalformed, "profile: type 46 needs SQ=0 and one object"},
		{"profile: two GI", cli, iFrame(0, 0, asdu(100, 2, cotAct, 0, 1, cat(ioa(0), []byte{20}, ioa(0), []byte{20})...)), eventfields.KindMalformed, "profile: type 100 needs SQ=0"},
		{"role: client sends 3", cli, iFrame(0, 0, asdu(3, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1})...)), eventfields.KindMalformed, "profile: client sent monitor-direction type 3"},
		{"role: client sends 1", cli, iFrame(0, 0, asdu(1, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1})...)), eventfields.KindMalformed, "profile: client sent monitor-direction type 1"},
		{"role: server activates 46", srv, iFrame(0, 0, asdu(46, 1, cotAct, 0, 1, cat(ioa(1), []byte{1})...)), eventfields.KindMalformed, "profile: server sent control type 46 with cause 6"},
		{"role: server deactivates 100", srv, iFrame(0, 0, asdu(100, 1, cotDeact, 0, 1, cat(ioa(0), []byte{20})...)), eventfields.KindMalformed, "profile: server sent system type 100 with cause 8"},
		{"unsupported 1 from server", srv, iFrame(0, 0, asdu(1, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1})...)), eventfields.KindUnsupported, "type 1 has no B descriptor"},
		{"unsupported 104", cli, iFrame(0, 0, asdu(104, 1, cotAct, 0, 1, cat(ioa(0), []byte{0xAA, 0x55})...)), eventfields.KindUnsupported, "type 104"},
		{"unsupported 106", cli, iFrame(0, 0, asdu(106, 1, cotAct, 0, 1, cat(ioa(0), []byte{0, 0})...)), eventfields.KindUnsupported, "type 106"},
		{"unsupported 255", srv, iFrame(0, 0, asdu(255, 0, 0, 0, 0)), eventfields.KindUnsupported, "type 255"},
	}
	for _, tc := range cases {
		evs := events(parseOne(t, tc.dir, tc.frame))
		if len(evs) != 1 {
			t.Fatalf("%s: %d events, want one per error APDU", tc.name, len(evs))
		}
		msg, _ := evs[0].Attributes[eventfields.KeyError].(string)
		if evs[0].Kind != tc.kind || !strings.Contains(msg, tc.err) {
			t.Errorf("%s: %s %q, want %s %q", tc.name, evs[0].Kind, msg, tc.kind, tc.err)
		}
		if strings.Contains(tc.err, "profile:") != strings.HasPrefix(msg, "profile: ") {
			t.Errorf("%s: profile prefix on %q", tc.name, msg)
		}
		if SafeRead(evs[0].Attributes) {
			t.Errorf("%s: SafeRead on an error event", tc.name)
		}
	}
}

// Header-only events keep the decoded header; unsupported types are class
// unknown and carry no object attributes. A role violation whose layout
// decoded keeps its first object as evidence.
func TestErrorEventEvidence(t *testing.T) {
	unsupported := events(parseOne(t, srv, iFrame(0, 0, asdu(1, 1, cotSpont, 0, 7, cat(ioa(1), []byte{1})...))))[0]
	checkAttrs(t, "unsupported", unsupported.Attributes, objWant{
		eventfields.KeyTypeID: uint8(1), eventfields.KeyClass: ClassUnknown, eventfields.KeyCA: uint16(7),
		eventfields.KeyCause: uint8(cotSpont), eventfields.KeyAPCIType: "I",
	}, eventfields.KeyIOA, eventfields.KeyIsWrite, eventfields.KeyValue)

	role := events(parseOne(t, srv, iFrame(0, 0, asdu(46, 1, cotAct, 0, 1, cat(ioa(2001), []byte{0x82})...))))[0]
	checkAttrs(t, "role", role.Attributes, objWant{
		eventfields.KeyIOA: uint32(2001), eventfields.KeySelect: true, eventfields.KeyValue: uint8(2),
		eventfields.KeyClass: ClassControl, eventfields.KeyIsWrite: false,
	})

	layout := events(parseOne(t, cli, iFrame(0, 0, asdu(46, 1, cotAct, 0, 1, cat(ioa(2001), []byte{0x80})...))))[0]
	checkAttrs(t, "layout", layout.Attributes, objWant{eventfields.KeyIsWrite: true, eventfields.KeyTypeID: uint8(46)}, eventfields.KeyIOA, eventfields.KeySelect)
}

// Role is the TCP role; cause is evidence only (spec §7.3).
func TestRoleAndCause(t *testing.T) {
	cases := []struct {
		name string
		dir  dpi.StreamDir
		asdu []byte
		kind string
	}{
		{"read COT 5", cli, asdu(102, 1, cotRequest, 0, 1, ioa(1)...), eventfields.KindRequest},
		{"end of init COT 4", srv, asdu(70, 1, cotInit, 0, 1, cat(ioa(0), []byte{0})...), eventfields.KindResponse},
		{"GI data COT 20", srv, asdu(3, 1, cotInrogen, 0, 1, cat(ioa(1), []byte{1})...), eventfields.KindResponse},
		{"periodic COT 1", srv, asdu(13, 1, 1, 0, 1, cat(ioa(1), f32(1), []byte{0})...), eventfields.KindResponse},
		{"command confirmation COT 7", srv, asdu(46, 1, cotActCon, 0, 1, cat(ioa(1), []byte{1})...), eventfields.KindResponse},
		{"command termination COT 10", srv, asdu(46, 1, cotActTerm, 0, 1, cat(ioa(1), []byte{1})...), eventfields.KindResponse},
		{"negative confirmation COT 46", srv, asdu(46, 1, cotUnknownCA|bitNegative, 0, 1, cat(ioa(1), []byte{1})...), eventfields.KindResponse},
		{"GI termination", srv, asdu(100, 1, cotActTerm, 0, 1, cat(ioa(0), []byte{20})...), eventfields.KindResponse},
		{"test-flagged client command", cli, asdu(46, 1, cotAct|bitTest|bitNegative, 0, 1, cat(ioa(1), []byte{1})...), eventfields.KindRequest},
		{"client deactivation", cli, asdu(46, 1, cotDeact, 0, 1, cat(ioa(1), []byte{1})...), eventfields.KindRequest},
	}
	for _, tc := range cases {
		ev := events(parseOne(t, tc.dir, iFrame(0, 0, tc.asdu)))[0]
		if ev.Kind != tc.kind {
			t.Errorf("%s: %s (%v)", tc.name, ev.Kind, ev.Attributes[eventfields.KeyError])
		}
	}
	// A server confirmation is a control-class response, never a write.
	conf := events(parseOne(t, srv, iFrame(0, 0, asdu(46, 1, cotActCon, 0, 1, cat(ioa(1), []byte{1})...))))[0]
	checkAttrs(t, "confirmation", conf.Attributes, objWant{eventfields.KeyClass: ClassControl, eventfields.KeyIsWrite: false, eventfields.KeyDirection: DirectionResponse})
}

func TestCP56(t *testing.T) {
	valid := []struct {
		name   string
		b      []byte
		time   string
		valid  bool
		summer bool
	}{
		{"course", courseTime, "2026-11-07T09:15:02.345", true, false},
		{"first", cp56(0, 1, 1, 0, 0, 0), "2000-01-01T00:00:00.000", true, false},
		{"last", cp56(99, 12, 31, 23, 59, 59999), "2099-12-31T23:59:59.999", true, false},
		{"leap day", cp56(24, 2, 29, 12, 0, 0), "2024-02-29T12:00:00.000", true, false},
		{"leap 2000", cp56(0, 2, 29, 12, 0, 0), "2000-02-29T12:00:00.000", true, false},
		{"IV", []byte{0, 0, 0x80 | 5, 1, 1, 1, 26}, "2026-01-01T01:05:00.000", false, false},
		{"SU", []byte{0, 0, 5, 0x80 | 1, 1, 1, 26}, "2026-01-01T01:05:00.000", true, true},
		{"GEN bit ignored", []byte{0, 0, 0x40 | 15, 1, 1, 1, 26}, "2026-01-01T01:15:00.000", true, false},
		{"day of week and reserved bits ignored", []byte{0, 0, 15, 0x60 | 1, 0xE0 | 7, 0xF0 | 3, 0x80 | 26}, "2026-03-07T01:15:00.000", true, false},
	}
	for _, tc := range valid {
		obj := map[string]any{}
		if err := decodeCP56(tc.b, obj); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		checkAttrs(t, tc.name, obj, objWant{eventfields.KeySourceTime: tc.time, eventfields.KeyTimeValid: tc.valid, eventfields.KeyTimeSummer: tc.summer})
	}
	invalid := []struct {
		name string
		b    []byte
		err  string
	}{
		{"year 100", cp56(100, 1, 1, 0, 0, 0), "year field 100"},
		{"year 127", cp56(127, 1, 1, 0, 0, 0), "year field 127"},
		{"no leap day", cp56(25, 2, 29, 0, 0, 0), "day 29 in 2025-02"},
		{"April 31", cp56(26, 4, 31, 0, 0, 0), "day 31 in 2026-04"},
		{"month 0", cp56(26, 0, 1, 0, 0, 0), "month 0"},
		{"month 13", cp56(26, 13, 1, 0, 0, 0), "month 13"},
		{"day 0", cp56(26, 1, 0, 0, 0, 0), "day 0"},
		{"ms 60000", cp56(26, 1, 1, 0, 0, 60000), "milliseconds 60000"},
		{"minute 60", cp56(26, 1, 1, 0, 60, 0), "minute 60"},
		{"hour 24", cp56(26, 1, 1, 24, 0, 0), "hour 24"},
	}
	for _, tc := range invalid {
		obj := map[string]any{}
		err := decodeCP56(tc.b, obj)
		if err == nil || !strings.Contains(err.Error(), tc.err) || len(obj) != 0 {
			t.Errorf("%s: err %v obj %v, want %q", tc.name, err, obj, tc.err)
		}
	}
}

func TestClassOf(t *testing.T) {
	want := map[uint8]string{
		3: ClassMonitor, 13: ClassMonitor, 31: ClassMonitor,
		45: ClassControl, 51: ClassControl, 58: ClassControl, 64: ClassControl,
		70: ClassSystem, 100: ClassSystem, 102: ClassSystem, 103: ClassSystem, 105: ClassSystem, 107: ClassSystem,
		0: ClassUnknown, 1: ClassUnknown, 30: ClassUnknown, 52: ClassUnknown, 104: ClassUnknown, 106: ClassUnknown, 255: ClassUnknown,
	}
	for typeID, class := range want {
		if got := ClassOf(typeID); got != class {
			t.Errorf("ClassOf(%d) = %s, want %s", typeID, got, class)
		}
	}
}
