// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func wireEvents(t *testing.T, message []byte) []dpi.Event {
	t.Helper()
	events, err := NewDecoder().OnPacket(cipState(), &dpi.ParsedPacket{
		Payload: buildEIPHeader(0x6f, 1, cpfMessage(message...)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func mspWire(code byte, children ...[]byte) []byte {
	data := make([]byte, 2+2*len(children))
	binary.LittleEndian.PutUint16(data, uint16(len(children)))
	for i, child := range children {
		binary.LittleEndian.PutUint16(data[2+2*i:], uint16(len(data)))
		data = append(data, child...)
	}
	if code&0x80 != 0 {
		return append([]byte{code, 0, 0x1e, 0}, data...)
	}
	return append([]byte{code, 0}, data...)
}

func TestResponseWireMetadata(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		wire := []byte{0xcd, 1, 5, 2, 0x34, 0x12, 0xcd, 0xab}
		wantWords := []uint16{0x1234, 0xabcd}
		if truncated {
			wire = wire[:7]
			wantWords = wantWords[:1]
		}
		ev := wireEvents(t, wire)[0]
		want := []string{"cip.response_reserved"}
		if truncated {
			want = append([]string{"cip.message_short"}, want...)
		}
		assertCodes(t, ev, want)
		if !reflect.DeepEqual(ev.Attributes["additional_status"], wantWords) {
			t.Fatal(ev.Attributes)
		}
		for form, attrs := range decodertest.Forms(t, ev.Attributes) {
			for key, want := range map[string]uint8{"response_reserved": 1, "general_status": 5, "additional_status_count": 2} {
				got, ok := eventfields.Uint8(attrs, key)
				if !ok || got != want {
					t.Fatalf("%s %s=%v", form, key, attrs[key])
				}
			}
			wordsJSON, err := json.Marshal(attrs["additional_status"])
			wantJSON, wantErr := json.Marshal(wantWords)
			if err != nil || wantErr != nil || string(wordsJSON) != string(wantJSON) {
				t.Fatalf("%s additional status=%s want=%s", form, wordsJSON, wantJSON)
			}
		}
	}
}

func TestMSPEmbeddedErrorAndChildIdentity(t *testing.T) {
	for _, wrapper := range []byte{0x0a, 0x8a} {
		evs := wireEvents(t, mspWire(wrapper, []byte{0xcc, 0, 0, 0}, []byte{0x4d, 0}))
		if len(evs) != 3 || evs[1].Kind != "response" || evs[2].Kind != "request" {
			t.Fatal(evs)
		}
		mismatch := 1
		if wrapper == 0x8a {
			mismatch = 2
		}
		assertCodes(t, evs[mismatch], []string{"cip.msp_response_mismatch"})
		assertCodes(t, evs[0], []string{"cip.msp_response_mismatch"})
		if evs[0].Attributes["multi_service_decoded_count"] != uint16(2) {
			t.Fatal(evs[0])
		}
		for _, ev := range evs[1:] {
			for form, attrs := range decodertest.Forms(t, ev.Attributes) {
				b, ok := eventfields.Bool(attrs, "msp")
				if !ok || !b {
					t.Fatalf("%s msp=%v", form, attrs["msp"])
				}
			}
		}
	}
}

func TestMSPSharedBudgetAndNesting(t *testing.T) {
	children := make([][]byte, 32)
	for i := range children {
		children[i] = []byte{0x4c, 0}
	}
	children[31] = []byte{0x4d, 0}
	evs := wireEvents(t, mspWire(0x0a, mspWire(0x0a, children...), []byte{0x4d, 0}))
	if len(evs) != 33 { // root + 32 globally budgeted children, not 32 per wrapper
		t.Fatalf("count=%d", len(evs))
	}
	assertCodes(t, evs[0], nil) // Limits are not wire violations.
	codes, _ := eventfields.Strings(evs[0].Attributes, eventfields.KeyUndecoded)
	if !slices.Equal(codes, []string{"cip.msp_limit"}) {
		t.Fatal(codes)
	}
	if !slices.Equal(evs[2].Attributes["msp_index_path"].([]uint16), []uint16{0, 0}) {
		t.Fatal(evs[2])
	}
	wire := []byte{0x4d, 0}
	for range maxMSPDepth + 2 {
		wire = mspWire(0x0a, wire)
	}
	evs = wireEvents(t, wire)
	codes, _ = eventfields.Strings(evs[0].Attributes, eventfields.KeyUndecoded)
	if !slices.Equal(codes, []string{"cip.msp_nesting"}) {
		t.Fatal(codes)
	}
	assertCodes(t, evs[0], nil)
}

func TestMSPDescendingOffsetsDoNotReparse(t *testing.T) {
	// Child 0's end precedes its start; child 1 would overlap that ambiguous
	// region. Only the later, unambiguous child 2 is retained.
	data := []byte{3, 0, 12, 0, 8, 0, 14, 0, 0x4d, 0, 0x4d, 0, 0x4d, 0, 0x4c, 0}
	result := ParseMSPServices(data)
	if len(result.Children) != 1 || result.Children[0].Index != 2 || len(result.Conformance) == 0 {
		t.Fatal(result)
	}
}

func TestCoverageIsNotConformance(t *testing.T) {
	for _, tc := range []struct {
		wire []byte
		code string
	}{
		{[]byte{0x4c, 1, 0xff, 0}, "cip.epath_unsupported"},
		{[]byte{0x7e, 0, 1, 2}, "cip.service_payload_unsupported"},
	} {
		ev := wireEvents(t, tc.wire)[0]
		assertCodes(t, ev, nil)
		codes, _ := eventfields.Strings(ev.Attributes, eventfields.KeyUndecoded)
		if !slices.Equal(codes, []string{tc.code}) {
			t.Fatal(ev)
		}
	}
	data := buildCPFItems(cpfTestItem{0, nil}, cpfTestItem{0xb2, []byte{0x4c, 0}}, cpfTestItem{0xb2, []byte{0x4d, 0}})
	r := parseCPF(data)
	if len(r.Items) != 3 || r.Selected != 1 || r.Err != nil || !slices.Equal(r.Undecoded, []string{"cip.extra_data_item"}) {
		t.Fatal(r)
	}
}

func TestConnectedProvenanceAndEncapsulationStatus(t *testing.T) {
	for _, seq := range []uint16{0, 1, 65535} {
		body := binary.LittleEndian.AppendUint16(nil, seq)
		body = append(body, 0xcc, 0, 0, 0)
		raw := buildEIPHeader(0x70, 1, buildCPFItems(cpfTestItem{0xa1, []byte{0x78, 0x56, 0x34, 0x12}}, cpfTestItem{0xb1, body}))
		evs, err := NewDecoder().OnPacket(cipState(), &dpi.ParsedPacket{Payload: raw})
		if err != nil || len(evs) != 1 || evs[0].Attributes["connected_sequence"] != seq || evs[0].Attributes["connection_id"] != uint32(0x12345678) {
			t.Fatal(evs, err)
		}
	}
	raw := buildEIPHeader(0x6f, 1, nil)
	binary.LittleEndian.PutUint32(raw[8:], 0x65)
	evs, _ := NewDecoder().OnPacket(cipState(), &dpi.ParsedPacket{Payload: raw})
	if evs[0].Attributes["enip_status"] != uint32(0x65) || evs[0].Attributes["general_status"] != nil {
		t.Fatal(evs)
	}
}

func TestCPFAddressAssociation(t *testing.T) {
	for _, items := range [][]cpfTestItem{
		{{0xb1, []byte{1, 0, 0x4c, 0}}, {0xa1, []byte{1, 0, 0, 0}}},
		{{0xa1, []byte{1, 0, 0, 0}}, {0xb2, []byte{0x4c, 0}}},
		{{0, []byte{1}}, {0xb2, []byte{0x4c, 0}}},
	} {
		r := parseCPF(buildCPFItems(items...))
		if r.Err == nil || r.ConnectionID != nil {
			t.Fatalf("invented valid association: %+v", r)
		}
	}
	r := parseCPF(buildCPFItems(cpfTestItem{0, nil}, cpfTestItem{0xb2, []byte{0x4c, 0}},
		cpfTestItem{0xa1, []byte{1, 0, 0, 0}}))
	if r.Err != nil || r.ConnectionID != nil {
		t.Fatalf("unrelated address was attached to selected B2: %+v", r)
	}
	bad := buildCPFItems(cpfTestItem{0, []byte{1}}, cpfTestItem{0xb2, []byte{0x4c, 0}},
		cpfTestItem{0x1234, []byte{1, 2}})
	evs, err := NewDecoder().OnPacket(cipState(), &dpi.ParsedPacket{Payload: buildEIPHeader(0x6f, 1, bad[:len(bad)-1])})
	if err != nil || len(evs) != 1 {
		t.Fatal(evs, err)
	}
	assertCodes(t, evs[0], []string{"cip.cpf_layout", "cip.item_truncated"})
}

func TestMalformedUDPEncapsulation(t *testing.T) {
	st := cipState()
	st.Key.Proto = 17
	raw := buildEIPHeader(0x6f, 1, cpfMessage(0x4c, 0))
	for _, payload := range [][]byte{nil, raw[:10], raw[:len(raw)-1]} {
		evs, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: payload})
		if err != nil || len(evs) != 1 || evs[0].Kind != eventfields.KindMalformed {
			t.Fatal(evs, err)
		}
	}
	evs, _ := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: append(raw, 1)})
	assertCodes(t, evs[0], []string{"cip.encapsulation_length"})
}
