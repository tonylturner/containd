// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
)

func captureFixtures(t testing.TB) []corpus.Fixture {
	t.Helper()
	fixtures, err := corpus.Load(os.DirFS("../../../.."), "test/cip/testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func replayCapture(t testing.TB, fixture corpus.Fixture, position corpus.PositionMode) ([]corpus.Step, map[string][]dpi.Event) {
	t.Helper()
	steps, err := corpus.Replay(func() *dpi.Manager { return dpi.NewManager(NewDecoder()) }, fixture,
		corpus.ReplayOptions{Position: position, FailClosed: true, SimulateHandshake: true})
	if err != nil {
		t.Fatal(err)
	}
	ordered := map[string][]dpi.Event{}
	for _, step := range steps {
		if step.Result.Err != nil || step.Result.Failed {
			t.Fatalf("%s: replay result %+v", fixture.Name, step.Result)
		}
		key := fmt.Sprintf("%s/%d", step.Packet.Connection, step.Packet.Dir)
		for _, event := range step.Result.Events {
			event.Timestamp = time.Time{}
			ordered[key] = append(ordered[key], event)
		}
	}
	return steps, ordered
}

func TestIndependentCaptures(t *testing.T) {
	for _, fixture := range captureFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			var baseline map[string][]dpi.Event
			for _, position := range []corpus.PositionMode{corpus.Sequence, corpus.SessionOffsets} {
				steps, semantics := replayCapture(t, fixture, position)
				checkCaptureOracle(t, fixture, steps)
				if baseline == nil {
					baseline = semantics
				} else if !reflect.DeepEqual(semantics, baseline) {
					t.Fatal("position modes changed ordered per-direction semantics")
				}
				if fixture.Spec.Transport != "tcp" {
					continue
				}
				var firstData int
				for i, packet := range fixture.Packets {
					if len(packet.Decoded.Payload) != 0 {
						firstData = i
						break
					}
				}
				for _, transform := range []corpus.Transform{
					corpus.Split(7), corpus.Coalesce(32768),
					corpus.Reorder(2, []int{1, 0}), corpus.Retransmit([]int{firstData}),
				} {
					derived, err := corpus.Apply(fixture, transform)
					if err != nil {
						t.Fatal(err)
					}
					_, got := replayCapture(t, derived, position)
					if !reflect.DeepEqual(got, baseline) {
						t.Fatalf("%v changed ordered per-direction semantics", derived.Derived)
					}
				}
				// Reorder actual split pieces too, not just already atomic PDUs.
				derived, err := corpus.Apply(fixture, corpus.Split(7), corpus.Reorder(3, []int{2, 0, 1}), corpus.Coalesce(32768))
				if err != nil {
					t.Fatal(err)
				}
				_, got := replayCapture(t, derived, position)
				if !reflect.DeepEqual(got, baseline) {
					t.Fatal("combined transforms changed semantics")
				}
			}
		})
	}
}

type captureExpectation struct {
	Frame   int                        `json:"frame"`
	Objects []captureObjectExpectation `json:"objects"`
}

type captureObjectExpectation struct {
	Kind        string   `json:"kind"`
	Conformance []string `json:"conformance"`
	Undecoded   []string `json:"undecoded"`
}

func checkCaptureOracle(t testing.TB, fixture corpus.Fixture, steps []corpus.Step) {
	t.Helper()
	events := map[int][]dpi.Event{}
	for _, step := range steps {
		if step.Kind == "inspect" && len(step.Packet.Source) != 0 {
			events[step.Packet.Source[0].Frame] = append(events[step.Packet.Source[0].Frame], step.Result.Events...)
		} else if len(step.Result.Events) != 0 {
			t.Fatal("unexpected lifecycle events")
		}
	}
	var expected []captureExpectation
	if err := json.Unmarshal(fixture.Expectations["events"], &expected); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, want := range expected {
		got := events[want.Frame]
		if len(got) != len(want.Objects) {
			t.Fatalf("frame %d: events=%v want objects=%v", want.Frame, got, want.Objects)
		}
		total += len(got)
		for i, event := range got {
			object := want.Objects[i]
			if event.Kind != object.Kind {
				t.Fatalf("frame %d object %d: kind=%s", want.Frame, i, event.Kind)
			}
			for key, codes := range map[string][]string{eventfields.KeyConformance: object.Conformance, eventfields.KeyUndecoded: object.Undecoded} {
				gotCodes, _ := eventfields.Strings(event.Attributes, key)
				if !reflect.DeepEqual(gotCodes, codes) && !(len(gotCodes) == 0 && len(codes) == 0) {
					t.Fatalf("frame %d object %d: %s=%v want=%v", want.Frame, i, key, gotCodes, codes)
				}
			}
		}
	}
	actual := 0
	for _, evs := range events {
		actual += len(evs)
	}
	if actual != total {
		t.Fatalf("unexpected event multiplicity %d want %d", actual, total)
	}
	for _, row := range fixture.Oracle {
		if row.Object >= len(events[row.Frame]) {
			t.Fatalf("oracle object lost: %+v", row)
		}
		event := events[row.Frame][row.Object]
		if event.Kind == eventfields.KindMalformed {
			// tshark can expose a partial encapsulation header. Our event
			// contract reports the unframeable datagram once, with raw bytes.
			raw := strings.ReplaceAll(row.Fields["udp.payload"], ":", "")
			if event.Attributes["raw_hex"] != raw {
				t.Fatalf("malformed datagram lost oracle bytes: %v", event.Attributes)
			}
			continue
		}
		for oracleKey, key := range map[string]string{
			"enip.command": "enip_command_code", "enip.status": "enip_status", "enip.session": "enip_session_handle",
			"cip.sc": "service_code", "cip.genstat": "general_status", "cip.class": "object_class",
			"cip.instance": "instance_id", "cip.attribute": "attribute_id", "cip.msp.num_services": "multi_service_count",
			"cip.addstat_size": "additional_status_count", "enip.cpf.itemcount": "cpf_item_count",
			"enip.cpf.cai.connid": "connection_id", "enip.cpf.sai.connid": "connection_id",
			"enip.cpf.sai.seq": "sequence",
		} {
			value := row.Fields[oracleKey]
			if value == "" {
				continue // Never invent path/status fields absent from the oracle.
			}
			want, err := strconv.ParseUint(value, 0, 32)
			if err != nil {
				t.Fatalf("oracle %s=%q: %v", oracleKey, value, err)
			}
			got, ok := eventfields.Uint32(event.Attributes, key)
			if !ok || got != uint32(want) {
				t.Fatalf("frame %d object %d: %s=%v oracle=%s", row.Frame, row.Object, key, event.Attributes[key], value)
			}
		}
		if bit := row.Fields["cip.rr"]; bit != "" {
			kind := "request"
			if bit != "0x00" {
				kind = "response"
			}
			if event.Kind != kind {
				t.Fatalf("frame %d: wire bit kind=%s got=%s", row.Frame, kind, event.Kind)
			}
		}
		checkCaptureStructuredOracle(t, fixture, row, event)
	}
}

func checkCaptureStructuredOracle(t testing.TB, fixture corpus.Fixture, row corpus.OracleRow, event dpi.Event) {
	t.Helper()
	if row.Fields["cip.sc"] != "" && row.Fields["cip.rr"] == "0x01" {
		var want []uint16
		if err := json.Unmarshal([]byte(row.Fields["additional_status.json"]), &want); err != nil {
			t.Fatal(err)
		}
		got, ok := event.Attributes["additional_status"].([]uint16)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("frame %d object %d: additional_status=%v oracle=%v", row.Frame, row.Object, got, want)
		}
		// tshark's size-zero request path annotations are not wire evidence.
		for _, key := range []string{"object_class", "instance_id", "attribute_id", "address"} {
			if _, present := event.Attributes[key]; present {
				t.Fatalf("response invented %s", key)
			}
		}
	}
	var types, lengths []uint16
	for key, target := range map[string]*[]uint16{"cpf_types.json": &types, "cpf_lengths.json": &lengths} {
		if err := json.Unmarshal([]byte(row.Fields[key]), target); err != nil {
			t.Fatal(err)
		}
	}
	if len(types) != 0 {
		names := make([]string, len(types))
		for i, item := range types {
			names[i] = fmt.Sprintf("0x%04x", item)
		}
		if event.Attributes["cpf_item_types"] != strings.Join(names, ",") {
			t.Fatalf("frame %d: CPF types=%v oracle=%v", row.Frame, event.Attributes["cpf_item_types"], types)
		}
	}
	if fixture.Spec.Transport == "tcp" && row.Fields["cip.seq"] != "" {
		want, err := strconv.ParseUint(row.Fields["cip.seq"], 0, 16)
		got, ok := eventfields.Uint16(event.Attributes, "connected_sequence")
		if err != nil || !ok || uint64(got) != want {
			t.Fatalf("frame %d: connected sequence=%v oracle=%v", row.Frame, got, want)
		}
	}
	if fixture.Name == "native-io" {
		got, ok := eventfields.Uint16(event.Attributes, "data_length")
		if !ok || len(lengths) != 2 || got != lengths[1] {
			t.Fatalf("frame %d: I/O length=%v oracle=%v", row.Frame, got, lengths)
		}
		payload, err := hex.DecodeString(strings.ReplaceAll(row.Fields["udp.payload"], ":", ""))
		if err != nil || len(payload) < 18 || event.Attributes["io_data_hex"] != hex.EncodeToString(payload[18:]) {
			t.Fatalf("frame %d: opaque I/O bytes differ from capture", row.Frame)
		}
		if event.Attributes["io_context_known"] != false {
			t.Fatal("inferred I/O context without connection tracking")
		}
		for _, key := range []string{"service_code", "function_code", "is_write", "transport_class", "cip_sequence"} {
			if _, present := event.Attributes[key]; present {
				t.Fatalf("opaque I/O invented %s", key)
			}
		}
	}
}
