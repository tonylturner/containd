// SPDX-License-Identifier: Apache-2.0
package modbus

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
)

func modbusCaptures(tb testing.TB) []corpus.Fixture {
	tb.Helper()
	fixtures, err := corpus.Load(os.DirFS("../../../.."), "test/modbus/testdata/manifest.json")
	if err != nil {
		tb.Fatal(err)
	}
	return fixtures
}

type captureExpectations struct {
	Events       int
	Conformance  map[string][]string
	Undecoded    map[string][]string
	FrameError   bool `json:"frame_error"`
	EOFPartial   bool `json:"eof_partial"`
	Supplemental map[string]map[string]uint16
}

func captureWants(t *testing.T, f corpus.Fixture) captureExpectations {
	t.Helper()
	b, err := json.Marshal(f.Expectations)
	if err != nil {
		t.Fatal(err)
	}
	var wants captureExpectations
	if err := json.Unmarshal(b, &wants); err != nil {
		t.Fatal(err)
	}
	return wants
}

type captureEvent struct {
	Kind  string
	Attrs map[string]any
}

// Normalize only transport-dependent visibility. The diagnostic identity,
// access fields, finding codes, ordering and multiplicity must all survive.
func semanticEvent(ev dpi.Event) captureEvent {
	attrs := map[string]any{}
	for k, v := range ev.Attributes {
		if k != "raw_hex" || ev.Kind != eventfields.KindMalformed {
			// Only malformed hex depends on the available prefix at failure.
			attrs[k] = v
		}
	}
	return captureEvent{ev.Kind, attrs}
}

func replayCapture(t *testing.T, f corpus.Fixture, position corpus.PositionMode, wants captureExpectations) ([]corpus.Step, map[string][]captureEvent) {
	t.Helper()
	steps, err := corpus.Replay(func() *dpi.Manager { return dpi.NewManager(NewDecoder()) }, f,
		corpus.ReplayOptions{Position: position, FailClosed: true, SimulateHandshake: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]captureEvent{}
	last := map[string]dpi.InspectResult{}
	events, failures := 0, 0
	for _, step := range steps {
		if step.Result.Err != nil {
			var fe *dpi.FrameError
			if !wants.FrameError || !errors.As(step.Result.Err, &fe) || fe.Reason != "invalid MBAP length 1" {
				t.Fatalf("%s: unexpected %s error: %v", f.Name, step.Kind, step.Result.Err)
			}
			failures++
		}
		if step.Kind != "inspect" {
			if len(step.Result.Events) != 0 {
				t.Fatalf("unexpected lifecycle events: %+v", step)
			}
			continue
		}
		key := fmt.Sprintf("%s/%d", step.Packet.Connection, step.Packet.Dir)
		if len(step.Packet.Decoded.Payload) > 0 {
			last[key] = step.Result
		}
		for _, ev := range step.Result.Events {
			if ev.Proto != eventfields.ProtoModbus {
				t.Fatal(ev)
			}
			got[key] = append(got[key], semanticEvent(ev))
			events++
		}
	}
	if events != wants.Events || (failures > 0) != wants.FrameError {
		t.Fatalf("%s: events=%d want=%d failures=%d", f.Name, events, wants.Events, failures)
	}
	partial := false
	for _, res := range last {
		if res.Gap {
			t.Fatal("unfilled transport gap at EOF")
		}
		partial = partial || res.NeedMore
	}
	if partial != wants.EOFPartial {
		t.Fatalf("EOF partial=%v want=%v", partial, wants.EOFPartial)
	}
	return steps, got
}

func TestReferenceCaptureManager(t *testing.T) {
	for _, fixture := range modbusCaptures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			wants := captureWants(t, fixture)
			var baseline map[string][]captureEvent
			for _, position := range []corpus.PositionMode{corpus.Sequence, corpus.SessionOffsets} {
				t.Run(fmt.Sprint(position), func(t *testing.T) {
					steps, got := replayCapture(t, fixture, position, wants)
					checkCaptureOracle(t, fixture, steps, wants)
					if baseline == nil {
						baseline = got
					} else if !reflect.DeepEqual(got, baseline) {
						t.Fatalf("position modes differ: got=%#v want=%#v", got, baseline)
					}
					var indices []int
					for i, p := range fixture.Packets {
						if len(p.Decoded.Payload) > 0 {
							indices = append(indices, i)
						}
					}
					for _, variant := range []struct {
						name       string
						transforms []corpus.Transform
					}{
						{"split", []corpus.Transform{corpus.Split(3)}},
						{"coalesce", []corpus.Transform{corpus.Split(3), corpus.Coalesce(32768)}},
						{"reorder", []corpus.Transform{corpus.Split(3), corpus.Reorder(2, []int{1, 0})}},
						{"retransmit", []corpus.Transform{corpus.Retransmit(indices)}},
					} {
						t.Run(variant.name, func(t *testing.T) {
							f, err := corpus.Apply(fixture, variant.transforms...)
							if err != nil {
								t.Fatal(err)
							}
							if len(f.Derived) != len(variant.transforms) {
								t.Fatal("missing transform provenance")
							}
							_, got := replayCapture(t, f, position, wants)
							if !reflect.DeepEqual(got, baseline) {
								t.Fatalf("ordered directional semantics changed:\ngot=%#v\nwant=%#v", got, baseline)
							}
						})
					}
				})
			}
		})
	}
}

func checkCaptureOracle(t *testing.T, f corpus.Fixture, steps []corpus.Step, wants captureExpectations) {
	t.Helper()
	byFrame := map[int]corpus.Step{}
	for _, step := range steps {
		if step.Kind == "inspect" && len(step.Packet.Decoded.Payload) > 0 {
			byFrame[step.Packet.Source[0].Frame] = step
		}
	}
	for _, row := range f.Oracle {
		step := byFrame[row.Frame]
		if wants.EOFPartial {
			if len(step.Result.Events) != 0 || !step.Result.NeedMore {
				t.Fatalf("truncated capture must remain incomplete: %+v", step.Result)
			}
			continue
		}
		if len(step.Result.Events) != 1 {
			t.Fatalf("frame %d: events=%v", row.Frame, step.Result.Events)
		}
		ev := step.Result.Events[0]
		frame := strconv.Itoa(row.Frame)
		for key, expected := range map[string][]string{
			eventfields.KeyConformance: wants.Conformance[frame],
			eventfields.KeyUndecoded:   wants.Undecoded[frame],
		} {
			got, _ := eventfields.Strings(ev.Attributes, key)
			if !slices.Equal(got, expected) {
				t.Fatalf("frame %d %s=%v want=%v", row.Frame, key, got, expected)
			}
		}
		if wants.FrameError {
			if ev.Kind != eventfields.KindMalformed || ev.Attributes["function_code"] != nil {
				t.Fatalf("unframeable header retained content: %+v", ev)
			}
			continue
		}
		kind := "request"
		if step.Packet.Dir == dpi.ServerToClient {
			kind = "response"
		}
		if row.Fields["modbus.exception_code"] != "" {
			kind = "exception"
		}
		if ev.Kind != kind {
			t.Fatalf("frame %d kind=%s want=%s", row.Frame, ev.Kind, kind)
		}
		expected := oracleAttributes(t, row)
		if kind == "response" && slices.Contains([]uint16{3, 4, 23}, expected["function_code"]) {
			if count, ok := expected["byte_count"]; ok {
				expected["register_count"] = count / 2
			}
		}
		for key, value := range wants.Supplemental[frame] {
			expected[key] = value
		}
		for key, value := range expected {
			got, ok := eventfields.Uint16(ev.Attributes, key)
			if !ok || got != value {
				t.Fatalf("frame %d %s=%v want=%d (oracle)", row.Frame, key, ev.Attributes[key], value)
			}
		}
		fc := expected["function_code"]
		write := slices.Contains([]uint16{5, 6, 15, 16, 21, 22, 23}, fc)
		known := write || slices.Contains([]uint16{1, 2, 3, 4, 7, 11, 12, 17, 20, 24}, fc)
		if fc == 8 && kind != "exception" {
			write = slices.Contains([]uint16{1, 3, 4, 10, 20}, expected["sub_function"])
			known = write || slices.Contains([]uint16{0, 2, 11, 12, 13, 14, 15, 16, 17, 18}, expected["sub_function"])
		}
		gotWrite, hasWrite := eventfields.Bool(ev.Attributes, eventfields.KeyIsWrite)
		if hasWrite != known || known && gotWrite != write {
			t.Fatalf("frame %d: write=%v/%v want=%v/%v", row.Frame, gotWrite, hasWrite, write, known)
		}
		checkOracleSpans(t, ev, expected, wants.Conformance[frame])
		if ev.Attributes["raw_hex"] != row.Fields["tcp.payload"] {
			t.Fatalf("frame %d raw payload mismatch", row.Frame)
		}
	}
}

func oracleAttributes(t *testing.T, row corpus.OracleRow) map[string]uint16 {
	t.Helper()
	out := map[string]uint16{}
	for field, key := range map[string]string{
		"mbtcp.trans_id": "transaction_id", "mbtcp.unit_id": "unit_id",
		"modbus.func_code": "function_code", "modbus.exception_code": "exception_code",
		"modbus.diagnostic_code": "sub_function", "modbus.reference_num": "address",
		"modbus.word_cnt": "quantity", "modbus.bit_cnt": "quantity", "modbus.byte_cnt": "byte_count",
		"modbus.read_reference_num": "read_address", "modbus.read_word_cnt": "read_quantity",
		"modbus.write_reference_num": "write_address", "modbus.write_word_cnt": "write_quantity",
		"modbus.and_mask": "and_mask", "modbus.or_mask": "or_mask",
	} {
		if s := row.Fields[field]; s != "" {
			base := 10
			if strings.HasPrefix(s, "0x") {
				base = 0
			}
			n, err := strconv.ParseUint(s, base, 16)
			if err != nil {
				t.Fatalf("frame %d nonscalar %s=%q: %v", row.Frame, field, s, err)
			}
			out[key] = uint16(n)
		}
	}
	// tshark calls a single register value out independently.
	if out["function_code"] == 6 {
		n, err := strconv.ParseUint(row.Fields["modbus.regval_uint16"], 10, 16)
		if err != nil {
			t.Fatal(err)
		}
		out["value"] = uint16(n)
	}
	if out["function_code"] == 5 {
		n, err := strconv.ParseUint(row.Fields["modbus.data"], 16, 16)
		if err != nil {
			t.Fatal(err)
		}
		out["value"] = uint16(n)
	}
	return out
}

func checkOracleSpans(t *testing.T, ev dpi.Event, fields map[string]uint16, codes []string) {
	t.Helper()
	fc := fields["function_code"]
	if ev.Kind == "response" && slices.Contains([]uint16{1, 2, 3, 4, 23}, fc) {
		for _, key := range []string{"address", "quantity", "read_address", "read_quantity", "write_address", "write_quantity"} {
			if _, ok := ev.Attributes[key]; ok {
				t.Fatalf("response invented request field %s", key)
			}
		}
	}
	var want []Span
	ok := false
	add := func(address, quantity uint16) {
		if quantity == 0 || uint32(address)+uint32(quantity) > 65536 {
			ok = false
			return
		}
		want = append(want, Span{address, uint16(uint32(address) + uint32(quantity) - 1)})
	}
	if !slices.Contains(codes, "modbus.pdu_layout") && ev.Kind != "exception" {
		switch fc {
		case 8:
			ok = true
		case 5, 6, 22:
			ok = true
			add(fields["address"], 1)
		case 1, 2, 3, 4, 15, 16:
			if _, present := fields["quantity"]; present {
				ok = true
				add(fields["address"], fields["quantity"])
			}
		case 23:
			if _, present := fields["read_quantity"]; present {
				ok = true
				add(fields["read_address"], fields["read_quantity"])
				add(fields["write_address"], fields["write_quantity"])
			}
		}
	}
	if fc == 8 && ev.Kind == "exception" {
		ok = true // diagnostics name no data address, even in an exception
	}
	spans, gotOK := AddressSpans(ev.Attributes)
	if gotOK != ok || !slices.Equal(spans, want) {
		t.Fatalf("%s: spans=%v/%v want=%v/%v", ev.Attributes["raw_hex"], spans, gotOK, want, ok)
	}
}
