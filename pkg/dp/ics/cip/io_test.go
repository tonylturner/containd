// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func ioCPF(items ...cpfTestItem) []byte {
	return buildCPFItems(items...)[6:] // bare count + items, no interface/timeout
}

func testIOPacket(payload []byte) []byte {
	return ioCPF(
		cpfTestItem{0x8002, []byte{0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x90}},
		cpfTestItem{0x00b1, payload},
	)
}

func TestUDPPortsAndDispatch(t *testing.T) {
	tcp, udp := NewDecoder().Ports()
	if !slices.Equal(tcp, []uint16{44818}) || !slices.Equal(udp, []uint16{2222, 44818}) {
		t.Fatalf("ports TCP=%v UDP=%v", tcp, udp)
	}
	for _, port := range []uint16{2222, 44818, 3333} {
		for _, reverse := range []bool{false, true} {
			st := cipState()
			st.Key.Proto, st.Key.DstPort = 17, port
			if reverse {
				st.Key = st.Key.Reversed()
			}
			if NewDecoder().Supports(st) != (port != 3333) {
				t.Fatalf("Supports port=%d reverse=%v", port, reverse)
			}
		}
	}
}

func TestNativeIOFields(t *testing.T) {
	for _, payload := range [][]byte{nil, {0x10}, {0x4c, 3, 0x20, 4, 0x24, 1, 0x30, 3}, make([]byte, 512)} {
		for _, reverse := range []bool{false, true} {
			st := cipState()
			st.Key.Proto, st.Key.DstPort = 17, 2222
			if reverse {
				st.Key = st.Key.Reversed()
			}
			events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: testIOPacket(payload)})
			if err != nil || len(events) != 1 || events[0].Kind != "session" || events[0].FlowID != st.Key.Hash() {
				t.Fatalf("events=%v err=%v", events, err)
			}
			assertCodes(t, events[0], nil)
			want := decodertest.Forms(t, map[string]any{
				"connection_id": uint32(0x12345678), "sequence": uint32(0x90abcdef),
				"data_length": uint16(len(payload)), "cpf_item_types": "0x8002,0x00b1",
			})
			for form, attrs := range decodertest.Forms(t, events[0].Attributes) {
				if !reflect.DeepEqual(attrs, want[form]) {
					t.Fatalf("%s attrs=%v", form, attrs)
				}
			}
		}
	}
}

func TestNativeIOMalformedCPF(t *testing.T) {
	valid := testIOPacket([]byte{0x10, 0, 1, 2})
	address := cpfTestItem{0x8002, []byte{1, 0, 0, 0, 2, 0, 0, 0}}
	data := cpfTestItem{0x00b1, []byte{0x10, 0, 1, 2}}
	badCount := slices.Clone(valid)
	binary.LittleEndian.PutUint16(badCount[:2], 3)
	cases := [][]byte{
		badCount,
		{0, 0},
		append(slices.Clone(valid), 0),
		ioCPF(address),
		ioCPF(data),
		ioCPF(data, address),
		ioCPF(address, address),
		ioCPF(data, data),
		ioCPF(cpfTestItem{0x00a1, address.data}, data),
		ioCPF(cpfTestItem{0x8002, address.data[:7]}, data),
		ioCPF(cpfTestItem{0x8002, append(slices.Clone(address.data), 0)}, data),
		ioCPF(address, cpfTestItem{0x00b2, data.data}),
		buildEIPHeader(0x6f, 1, cpfMessage(0x10, 0)), // never fall back to encapsulation
	}
	for cut := 0; cut < len(valid); cut++ {
		cases = append(cases, valid[:cut])
	}
	// Item types are reported in wire order up to the first unreadable item,
	// exactly as the encapsulated CPF layer reports them.
	wantTypes := map[int]string{
		0: "0x8002,0x00b1", 2: "0x8002,0x00b1", 3: "0x8002", 4: "0x00b1", 5: "0x00b1,0x8002", 8: "0x00a1,0x00b1",
	}
	for i, wire := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			st := cipState()
			st.Key.Proto, st.Key.DstPort = 17, 2222
			events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: wire})
			if err != nil || len(events) != 1 {
				t.Fatalf("events=%v err=%v", events, err)
			}
			assertCodes(t, events[0], []string{"cip.cpf_layout"})
			if want, ok := wantTypes[i]; ok && events[0].Attributes["cpf_item_types"] != want {
				t.Fatalf("cpf_item_types=%v want %q", events[0].Attributes["cpf_item_types"], want)
			}
			for _, key := range []string{"enip_command_code", "service_code", "function_code", "is_write", "object_class"} {
				if _, present := events[0].Attributes[key]; present {
					t.Fatalf("invented %s", key)
				}
			}
			// An intact twin immediately after a malformed datagram must
			// decode independently: UDP carries no inter-packet state.
			events, err = NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: valid})
			if err != nil || len(events) != 1 {
				t.Fatalf("twin events=%v err=%v", events, err)
			}
			assertCodes(t, events[0], nil)
		})
	}
}

func TestNativeIOPartialFields(t *testing.T) {
	raw := testIOPacket([]byte{1, 2, 3})
	for _, tc := range []struct {
		cut  int
		keys []string
	}{
		{5, nil}, // incomplete address-item header
		{9, nil}, // incomplete connection id
		{10, []string{"connection_id"}},
		{13, []string{"connection_id"}},
		{14, []string{"connection_id", "sequence"}},
		{len(raw) - 1, []string{"connection_id", "sequence"}},
	} {
		st := cipState()
		st.Key.Proto, st.Key.DstPort = 17, 2222
		events, _ := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: raw[:tc.cut]})
		for _, key := range []string{"connection_id", "sequence", "data_length"} {
			_, present := events[0].Attributes[key]
			if present != slices.Contains(tc.keys, key) {
				t.Fatalf("cut=%d key=%s attrs=%v", tc.cut, key, events[0].Attributes)
			}
		}
	}
}

func TestUDPEncapsulatedDiscovery(t *testing.T) {
	for _, command := range []uint16{0x0001, 0x0004, 0x0063} {
		for _, reverse := range []bool{false, true} {
			st := cipState()
			st.Key.Proto, st.Key.DstPort = 17, 44818
			if reverse {
				st.Key = st.Key.Reversed()
			}
			events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: buildEIPHeader(command, 0, nil)})
			if err != nil || len(events) != 1 {
				t.Fatalf("events=%v err=%v", events, err)
			}
			assertEncapsulation(t, events[0].Attributes, command, 0)
			assertCodes(t, events[0], nil)
		}
	}
}

func FuzzNativeIO(f *testing.F) {
	f.Add([]byte{})
	f.Add(testIOPacket([]byte{0x10, 0, 1, 2}))
	f.Add(testIOPacket(nil))
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, wire []byte) {
		st := cipState()
		st.Key.Proto, st.Key.DstPort = 17, 2222
		events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: wire})
		if err != nil || len(events) != 1 {
			t.Fatalf("events=%v err=%v", events, err)
		}
		if _, present := events[0].Attributes["service_code"]; present {
			t.Fatal("I/O bytes interpreted as service")
		}
	})
}
