// SPDX-License-Identifier: Apache-2.0

package cip

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

type cpfTestItem struct {
	typeID uint16
	data   []byte
}

func buildCPFItems(items ...cpfTestItem) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint16(data[6:8], uint16(len(items)))
	for _, item := range items {
		data = binary.LittleEndian.AppendUint16(data, item.typeID)
		data = binary.LittleEndian.AppendUint16(data, uint16(len(item.data)))
		data = append(data, item.data...)
	}
	return data
}

func assertEncapsulation(t *testing.T, attrs map[string]any, command uint16, session uint32) {
	t.Helper()
	for key, want := range map[string]any{
		"enip_command":        CommandName(command),
		"enip_command_code":   command,
		"enip_session_handle": session,
	} {
		if attrs[key] != want {
			t.Errorf("%s = %v, want %v", key, attrs[key], want)
		}
	}
	for _, old := range []string{"command", "command_code", "session_handle"} {
		if _, ok := attrs[old]; ok {
			t.Errorf("obsolete alias %s emitted", old)
		}
	}
}

func TestDecoderEtherNetIPLayers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command uint16
		data    []byte
		types   string
		cpf     bool
	}{
		{"SendRRData", 0x006f, buildSendRRDataPayload(0x4c, 0, nil), "0x0000,0x00b2", true},
		// The connected payload includes its sequence count. This test only
		// asserts framing metadata, not the service interpretation.
		{"SendUnitData", 0x0070, buildCPFItems(
			cpfTestItem{0x00a1, []byte{1, 0, 0, 0}},
			cpfTestItem{0x00b1, []byte{1, 0, 0x4c, 0}},
		), "0x00a1,0x00b1", true},
		{"RegisterSession", 0x0065, []byte{1, 0, 0, 0}, "", false},
		{"after CIP", 0x006f, buildCPFItems(
			cpfTestItem{0x00b2, []byte{0x4c, 0}},
			cpfTestItem{0x1234, []byte{1}},
			cpfTestItem{0x00b2, []byte{0x4d, 0}},
		), "0x00b2,0x1234,0x00b2", true},
		{"no CIP", 0x006f, buildCPFItems(cpfTestItem{0x0000, nil}), "0x0000", true},
		{"invalid CIP", 0x006f, buildCPFItems(cpfTestItem{0x00b2, nil}), "0x00b2", true},
		{"empty CPF", 0x0070, buildCPFItems(), "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 44818, 6), time.Now())
			events, err := NewDecoder().OnPacket(state, &dpi.ParsedPacket{
				Payload: buildEIPHeader(tc.command, 0x12345678, tc.data),
			})
			if err != nil || len(events) != 1 {
				t.Fatalf("events=%v err=%v", events, err)
			}
			ev := events[0]
			if ev.Proto != "cip" {
				t.Fatalf("protocol = %q", ev.Proto)
			}
			assertEncapsulation(t, ev.Attributes, tc.command, 0x12345678)
			types, present := ev.Attributes["cpf_item_types"]
			if tc.cpf && types != tc.types {
				t.Errorf("CPF types=%v, want %v", types, tc.types)
			}
			if present != tc.cpf {
				t.Errorf("CPF field present=%t, want %t", present, tc.cpf)
			}
			if tc.name == "after CIP" && ev.Attributes["service_code"] != uint8(0x4c) {
				t.Error("did not retain first CIP item")
			}
		})
	}
}

func TestDecoderMalformedCPF(t *testing.T) {
	valid := buildSendRRDataPayload(0x4c, 0, nil)
	trailing := buildCPFItems(cpfTestItem{0x00b2, []byte{0x4c, 0}}, cpfTestItem{0x1234, []byte{1}})
	for _, data := range [][]byte{
		valid[:7],
		valid[:len(valid)-1],
		// A valid first CIP item must not hide malformed later items.
		trailing[:len(trailing)-1],
	} {
		if _, _, err := parseCPF(data); err == nil {
			t.Fatal("malformed CPF accepted")
		}
		state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 44818, 6), time.Now())
		events, err := NewDecoder().OnPacket(state, &dpi.ParsedPacket{Payload: buildEIPHeader(0x006f, 1, data)})
		if err != nil || len(events) != 1 {
			t.Fatalf("events=%v err=%v", events, err)
		}
		if _, ok := events[0].Attributes["cpf_item_types"]; ok {
			t.Fatal("partial CPF item list emitted")
		}
		if len(data) == len(trailing)-1 {
			msg, err := ParseCIPMessage(data)
			if err != nil || msg.ServiceCode != 0x4c || events[0].Attributes["service_code"] != uint8(0x4c) {
				t.Fatal("malformed later item changed first CIP payload decoding")
			}
		}
	}
}
