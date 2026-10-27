// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func cpfMessage(b ...byte) []byte { return buildCPFItems(cpfTestItem{0xb2, b}) }

func assertCodes(t *testing.T, ev dpi.Event, want []string) {
	t.Helper()
	for form, a := range decodertest.Forms(t, ev.Attributes) {
		got, _ := eventfields.Strings(a, eventfields.KeyConformance)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s codes=%v want=%v attrs=%v", form, got, want, a)
		}
	}
}

func TestConformanceTwins(t *testing.T) {
	valid := cpfMessage(0x4c, 0)
	trailing := append(append([]byte(nil), valid...), 0)
	nonzeroInterface := append([]byte(nil), valid...)
	nonzeroInterface[0] = 1
	for _, tc := range []struct {
		name, code string
		command    uint16
		bad, good  []byte
	}{
		{"command", "cip.unknown_command", 0xffff, nil, nil},
		{"short CPF", "cip.cpf_layout", 0x6f, valid[:7], valid},
		{"empty CPF", "cip.cpf_layout", 0x6f, nil, valid},
		{"no CIP", "cip.cpf_layout", 0x6f, buildCPFItems(cpfTestItem{0, nil}), valid},
		{"trailing CPF", "cip.cpf_layout", 0x6f, trailing, valid},
		{"invalid interface", "cip.cpf_layout", 0x6f, nonzeroInterface, valid},
		{"short item header", "cip.cpf_layout", 0x6f, valid[:11], valid},
		{"short item body", "cip.item_truncated", 0x6f, valid[:len(valid)-1], valid},
		{"empty message", "cip.message_short", 0x6f, cpfMessage(), valid},
		{"service only", "cip.message_short", 0x6f, cpfMessage(0x4c), valid},
		{"response header", "cip.message_short", 0x6f, cpfMessage(0xcc, 0), cpfMessage(0xcc, 0, 0, 0)},
		{"response additional status", "cip.message_short", 0x6f, cpfMessage(0xcc, 0, 0, 1), cpfMessage(0xcc, 0, 0, 1, 0, 0)},
		{"path length", "cip.epath_truncated", 0x6f, cpfMessage(0x4c, 2, 0x20, 4), cpfMessage(0x4c, 1, 0x20, 4)},
		{"path segment", "cip.epath_truncated", 0x6f, cpfMessage(0x4c, 1, 0x21, 0), cpfMessage(0x4c, 2, 0x21, 0, 4, 0)},
		{"symbol segment", "cip.epath_truncated", 0x6f, cpfMessage(0x4c, 1, 0x91, 2), cpfMessage(0x4c, 2, 0x91, 2, 'a', 'b')},
		{"MSP offsets", "cip.msp_layout", 0x6f, cpfMessage(0x0a, 0, 1, 0), cpfMessage(0x0a, 0, 1, 0, 4, 0, 0x4c, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, bad := range []bool{true, false} {
				data, cmd := tc.good, tc.command
				if bad {
					data = tc.bad
				} else if cmd == 0xffff {
					cmd = 0x65
				}
				raw := buildEIPHeader(cmd, 1, data)
				next := buildEIPHeader(0x6f, 1, valid)
				res, err := NewDecoder().ParseStream(cipState(), dpi.StreamView{Bytes: append(raw, next...)})
				if err != nil || len(res.Frames) != 2 || res.Consumed != len(raw)+len(next) {
					t.Fatalf("boundary %+v %v", res, err)
				}
				var want []string
				if bad {
					want = []string{tc.code}
				}
				assertCodes(t, res.Frames[0].Events[0], want)
				udpState := cipState()
				udpState.Key.Proto, udpState.Key.DstPort = 17, 2222
				events, err := NewDecoder().OnPacket(udpState, &dpi.ParsedPacket{Payload: raw})
				if err != nil || len(events) != len(res.Frames[0].Events) {
					t.Fatalf("UDP events=%v err=%v", events, err)
				}
				assertCodes(t, events[0], want)
			}
		})
	}
}

func TestPartialFieldsAndSortedFindings(t *testing.T) {
	data := append(cpfMessage(0x4c, 2, 0x20, 4), 0)
	res, err := NewDecoder().ParseStream(cipState(), dpi.StreamView{Bytes: buildEIPHeader(0x6f, 1, data)})
	if err != nil {
		t.Fatal(err)
	}
	ev := res.Frames[0].Events[0]
	assertCodes(t, ev, []string{"cip.cpf_layout", "cip.epath_truncated"})
	if ev.Attributes["service_code"] != uint8(0x4c) || ev.Attributes["object_class"] != uint16(4) {
		t.Fatal(ev)
	}
	for _, key := range []string{"instance_id", "attribute_id", "address"} {
		if _, ok := ev.Attributes[key]; ok {
			t.Fatalf("invented %s", key)
		}
	}
}

func TestConnectedSequenceIsNotService(t *testing.T) {
	data := buildCPFItems(cpfTestItem{0xa1, []byte{1, 0, 0, 0}}, cpfTestItem{0xb1, []byte{0xff, 0xff, 0x4c, 0}})
	events, err := NewDecoder().OnPacket(cipState(), &dpi.ParsedPacket{Payload: buildEIPHeader(0x70, 1, data)})
	if err != nil || len(events) != 1 || events[0].Attributes["service_code"] != uint8(0x4c) {
		t.Fatalf("%v %v", events, err)
	}
	assertCodes(t, events[0], nil)
}

func TestMSPSubserviceFinding(t *testing.T) {
	data := cpfMessage(0x0a, 0, 1, 0, 4, 0, 0x4c, 2, 0x20, 4)
	events, err := NewDecoder().OnPacket(cipState(), &dpi.ParsedPacket{Payload: buildEIPHeader(0x6f, 1, data)})
	if err != nil || len(events) != 2 {
		t.Fatalf("%v %v", events, err)
	}
	assertCodes(t, events[1], []string{"cip.epath_truncated"})
	assertCodes(t, events[0], []string{"cip.epath_truncated"})
}

func TestEncapsulationErrorAndNopDoNotRequireCPF(t *testing.T) {
	for _, cmd := range []uint16{0, 0x6f} {
		wire := buildEIPHeader(cmd, 1, nil)
		if cmd == 0x6f {
			binary.LittleEndian.PutUint32(wire[8:12], 1)
		}
		events, err := NewDecoder().OnPacket(cipState(), &dpi.ParsedPacket{Payload: wire})
		if err != nil || len(events) != 1 {
			t.Fatalf("%v %v", events, err)
		}
		assertCodes(t, events[0], nil)
	}
}

func TestMSPErrorResponseDoesNotRequireServices(t *testing.T) {
	wire := buildEIPHeader(0x6f, 1, cpfMessage(0x8a, 0, 1, 0))
	events, err := NewDecoder().OnPacket(cipState(), &dpi.ParsedPacket{Payload: wire})
	if err != nil || len(events) != 1 {
		t.Fatalf("%v %v", events, err)
	}
	assertCodes(t, events[0], nil)
	if events[0].Attributes["general_status"] != uint8(1) {
		t.Fatal("lost response status")
	}
}
