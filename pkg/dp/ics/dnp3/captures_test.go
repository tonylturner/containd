// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
)

func referenceFixtures(t testing.TB) []corpus.Fixture {
	t.Helper()
	fixtures, err := corpus.Load(os.DirFS("../../../../test/dnp3/testdata"), "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}
	for _, fixture := range fixtures {
		present[fixture.Name] = true
	}
	for _, name := range []string{"link-only", "startup-integrity", "class-range", "unsolicited", "crob", "iin-error", "large-response", "crc-flip", "header-crc", "qualifier-tail"} {
		if !present[name] {
			t.Fatalf("required independent scenario %s missing", name)
		}
	}
	return fixtures
}

type captureCROB struct {
	Control uint8  `json:"control"`
	Count   uint8  `json:"count"`
	OnTime  uint32 `json:"on_time_ms"`
	OffTime uint32 `json:"off_time_ms"`
	Status  uint8  `json:"status"`
}
type capturePoint struct {
	Index *uint32      `json:"index,omitempty"`
	CROB  *captureCROB `json:"crob,omitempty"`
}
type captureHeader struct {
	HasCount                    bool
	Group, Variation, Qualifier byte
	Count                       uint64
	Start, Stop                 *uint32
	Points                      []capturePoint
}
type captureSemantic struct {
	Malformed           bool
	Source, Destination uint16
	HasFunction         bool
	Function, Sequence  byte
	FIR, FIN, CON, UNS  bool
	IIN                 *uint16
	Objects             []captureHeader
}
type captureTrace struct {
	FrameErrors map[string][]string
	Semantics   map[string][]captureSemantic
	FrameSizes  map[string][]int64
	Findings    map[string][]string
}

func captureDirection(p corpus.Packet) string { return fmt.Sprintf("%s/%d", p.Connection, p.Dir) }
func oracleUint(t testing.TB, text string, bits int) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(text, 0, bits)
	if err != nil {
		t.Fatalf("oracle integer %q: %v", text, err)
	}
	return n
}
func oracleBool(t testing.TB, text string) bool {
	t.Helper()
	switch text {
	case "True":
		return true
	case "False":
		return false
	default:
		t.Fatalf("oracle boolean %q", text)
		return false
	}
}
func oracleIndex(t testing.TB, text string) *uint32 {
	t.Helper()
	if text == "" {
		return nil
	}
	v := uint32(oracleUint(t, text, 32))
	return &v
}

type captureMutation struct {
	Parent   string `json:"parent"`
	Mode     string `json:"mode"`
	Frame    int    `json:"frame"`
	NewValue uint8  `json:"new_value"`
	Unframed int64  `json:"unframed_payload_bytes"`
}

func oracleSemantics(t testing.TB, f corpus.Fixture) map[string][]captureSemantic {
	return oracleSemanticsMutation(t, f, nil)
}
func oracleSemanticsMutation(t testing.TB, f corpus.Fixture, mutation *captureMutation) map[string][]captureSemantic {
	t.Helper()
	directions := map[int]string{}
	for _, p := range f.Packets {
		for _, span := range p.Source {
			directions[span.Frame] = captureDirection(p)
		}
	}
	result := map[string][]captureSemantic{}
	last := ""
	for _, row := range f.Oracle {
		fields := row.Fields
		if mutation != nil && mutation.Mode == "header-crc" && row.Frame >= mutation.Frame {
			if row.Frame == mutation.Frame && row.PDU == 0 && row.Object == 0 {
				key := directions[row.Frame]
				if key == "" {
					t.Fatal("unattributed mutation")
				}
				result[key] = append(result[key], captureSemantic{Malformed: true})
			}
			continue
		}
		if fields["dnp3.al.func"] == "" {
			continue
		}
		key := directions[row.Frame]
		if key == "" {
			t.Fatalf("unattributed oracle frame %d", row.Frame)
		}
		id := fmt.Sprintf("%d/%d", row.Frame, row.PDU)
		if id != last {
			ev := captureSemantic{Source: uint16(oracleUint(t, fields["dnp3.src"], 16)), Destination: uint16(oracleUint(t, fields["dnp3.dst"], 16)), HasFunction: true,
				Function: byte(oracleUint(t, fields["dnp3.al.func"], 8)), Sequence: byte(oracleUint(t, fields["dnp3.al.seq"], 4)),
				FIR: oracleBool(t, fields["dnp3.al.fir"]), FIN: oracleBool(t, fields["dnp3.al.fin"]), CON: oracleBool(t, fields["dnp3.al.con"]), UNS: oracleBool(t, fields["dnp3.al.uns"])}
			if fields["dnp3.al.iin"] != "" {
				iin := uint16(oracleUint(t, fields["dnp3.al.iin"], 16))
				ev.IIN = &iin
			}
			result[key] = append(result[key], ev)
			last = id
		}
		if fields["group"] == "" {
			continue
		}
		h := captureHeader{HasCount: true, Group: byte(oracleUint(t, fields["group"], 8)), Variation: byte(oracleUint(t, fields["variation"], 8)), Qualifier: byte(oracleUint(t, fields["qualifier"], 8)),
			Start: oracleIndex(t, fields["start"]), Stop: oracleIndex(t, fields["stop"])}
		if h.Start != nil && h.Stop != nil {
			h.Count = uint64(*h.Stop) - uint64(*h.Start) + 1
		} else if fields["quantity"] != "" {
			h.Count = oracleUint(t, fields["quantity"], 32)
		}
		if err := json.Unmarshal([]byte(fields["points.json"]), &h.Points); err != nil {
			t.Fatal(err)
		}
		if len(h.Points) == 0 {
			h.Points = nil
		}
		if mutation != nil && mutation.Mode == "qualifier" && row.Frame == mutation.Frame && row.PDU == 0 {
			if row.Object != 0 {
				continue
			} // declared uninspected tail, not guessed headers
			h.Qualifier = mutation.NewValue
			h.HasCount = false
			h.Count = 0
			h.Start = nil
			h.Stop = nil
			h.Points = nil
		}
		n := len(result[key]) - 1
		result[key][n].Objects = append(result[key][n].Objects, h)
	}
	return result
}
func decodedSemantic(t testing.TB, attrs map[string]any) captureSemantic {
	t.Helper()
	source, ok := eventfields.Uint16(attrs, "source_address")
	if !ok {
		t.Fatal("missing source")
	}
	destination, ok := eventfields.Uint16(attrs, "destination_address")
	if !ok {
		t.Fatal("missing destination")
	}
	fc, has := eventfields.Uint8(attrs, eventfields.KeyFunctionCode)
	ev := captureSemantic{Source: source, Destination: destination, HasFunction: has, Function: fc}
	if !has {
		return ev
	}
	ev.Sequence, _ = eventfields.Uint8(attrs, "application_sequence")
	ev.FIR, _ = eventfields.Bool(attrs, "application_fir")
	ev.FIN, _ = eventfields.Bool(attrs, "application_fin")
	ev.CON, _ = eventfields.Bool(attrs, "application_con")
	ev.UNS, _ = eventfields.Bool(attrs, "application_uns")
	if iin1, ok := eventfields.Uint8(attrs, "iin1"); ok {
		iin2, ok := eventfields.Uint8(attrs, "iin2")
		if !ok {
			t.Fatal("partial IIN")
		}
		iin := uint16(iin1)<<8 | uint16(iin2)
		ev.IIN = &iin
	}
	headers, _ := attrs["objects"].([]ObjectHeader)
	for _, h := range headers {
		header := captureHeader{HasCount: h.HasCount, Group: h.Group, Variation: h.Variation, Qualifier: h.Qualifier, Count: h.Count, Start: h.Start, Stop: h.Stop}
		for _, p := range h.Points {
			point := capturePoint{Index: p.Index}
			if v := p.CROB; v != nil {
				point.CROB = &captureCROB{v.Control, v.Count, v.OnTime, v.OffTime, v.Status}
			}
			header.Points = append(header.Points, point)
		}
		ev.Objects = append(ev.Objects, header)
	}
	return ev
}
func replayCapture(t testing.TB, f corpus.Fixture, position corpus.PositionMode) captureTrace {
	t.Helper()
	makeManager := func() *dpi.Manager {
		return dpi.NewManager(NewDecoderWithClock(func() time.Time { return time.Unix(1, 0) }))
	}
	steps, err := corpus.Replay(makeManager, f, corpus.ReplayOptions{Position: position, FailClosed: true, SimulateHandshake: true})
	if err != nil {
		t.Fatal(err)
	}
	trace := captureTrace{Semantics: map[string][]captureSemantic{}, FrameSizes: map[string][]int64{}, Findings: map[string][]string{}, FrameErrors: map[string][]string{}}
	var expectedError string
	if value := f.Expectations["frame_error"]; value != nil {
		if err := json.Unmarshal(value, &expectedError); err != nil {
			t.Fatal(err)
		}
	}
	for _, step := range steps {
		key := captureDirection(step.Packet)
		if step.Result.Err != nil || step.Result.Failed {
			var fe *dpi.FrameError
			if expectedError == "" || !errors.As(step.Result.Err, &fe) || fe.Reason != expectedError {
				t.Fatalf("%s frame %+v: %+v", step.Kind, step.Packet.Source, step.Result)
			}
			if !step.Result.Failed {
				trace.FrameErrors[key] = append(trace.FrameErrors[key], fe.Reason)
			}
		}
		for _, frame := range step.Result.Frames {
			trace.FrameSizes[key] = append(trace.FrameSizes[key], frame.End-frame.Start)
		}
		for _, event := range step.Result.Events {
			if event.Proto != eventfields.ProtoDNP3 {
				t.Fatalf("unexpected event %+v", event)
			}
			if event.Kind == eventfields.KindMalformed {
				if expectedError == "" {
					t.Fatal("unexpected malformed event", event)
				}
				for _, field := range []string{eventfields.KeyFunctionCode, "source_address", "destination_address", "objects"} {
					if _, exists := event.Attributes[field]; exists {
						t.Fatalf("invented malformed evidence %s", field)
					}
				}
				trace.Semantics[key] = append(trace.Semantics[key], captureSemantic{Malformed: true})
			} else {
				trace.Semantics[key] = append(trace.Semantics[key], decodedSemantic(t, event.Attributes))
			}
			for _, findingKey := range []string{eventfields.KeyConformance, eventfields.KeyUndecoded} {
				codes, _ := eventfields.Strings(event.Attributes, findingKey)
				trace.Findings[findingKey] = append(trace.Findings[findingKey], codes...)
			}
		}
	}
	if expectedError != "" {
		count := 0
		for _, codes := range trace.FrameErrors {
			count += len(codes)
		}
		if count != 1 {
			t.Fatalf("expected one framing error, got %v", trace.FrameErrors)
		}
	}
	return trace
}
func assertCaptureFindings(t testing.TB, f corpus.Fixture, trace captureTrace) {
	t.Helper()
	for _, key := range []string{eventfields.KeyConformance, eventfields.KeyUndecoded} {
		var want []string
		if err := json.Unmarshal(f.Expectations[key], &want); err != nil {
			t.Fatal(err)
		}
		got := slices.Compact(slices.Sorted(slices.Values(trace.Findings[key])))
		if !slices.Equal(got, want) {
			t.Fatalf("%s findings %v, want %v", key, got, want)
		}
	}
}

func TestReferenceCapture(t *testing.T) {
	fixtures := referenceFixtures(t)
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			want := oracleSemantics(t, f)
			if mutation := f.Expectations["mutation"]; mutation != nil {
				// Derive mutation expectations only from the authenticated good
				// parent and byte recipe. A data CRC changes no user bytes; a
				// reserved qualifier stops the walk; a bad header CRC exposes
				// no content, even when Wireshark displays candidate fields.
				var meta captureMutation
				if err := json.Unmarshal(mutation, &meta); err != nil {
					t.Fatal(err)
				}
				found := false
				for _, parent := range fixtures {
					if parent.Spec.PCAP == meta.Parent {
						want = oracleSemanticsMutation(t, parent, &meta)
						found = true
						// Incarnation IDs include fixture names, not protocol semantics.
						remapped := map[string][]captureSemantic{}
						for key, events := range want {
							remapped[f.Name+key[len(parent.Name):]] = events
						}
						want = remapped
					}
				}
				if !found {
					t.Fatalf("unknown mutation parent %q", meta.Parent)
				}
			}
			baseline := replayCapture(t, f, corpus.Sequence)
			assertCaptureFindings(t, f, baseline)
			if !reflect.DeepEqual(baseline.Semantics, want) {
				t.Fatalf("decoded semantics:\n%+v\noracle:\n%+v", baseline.Semantics, want)
			}
			// Every unique captured byte must belong to a physical frame, including
			// link-only and nonfinal transport segments. No silent EOF tail is allowed.
			totals := map[string]int64{}
			for _, p := range f.Packets {
				totals[captureDirection(p)] += int64(len(p.Decoded.Payload))
			}
			for key, total := range totals {
				var framed int64
				for _, size := range baseline.FrameSizes[key] {
					framed += size
				}
				unframed := int64(0)
				if raw := f.Expectations["mutation"]; raw != nil {
					var meta captureMutation
					if err := json.Unmarshal(raw, &meta); err != nil {
						t.Fatal(err)
					}
					if len(baseline.FrameErrors[key]) > 0 {
						unframed = meta.Unframed
					}
				}
				if framed+unframed != total {
					t.Fatalf("%s framed %d plus declared unframeable %d of %d bytes", key, framed, unframed, total)
				}
			}
			split, err := corpus.Apply(f, corpus.Split(7))
			if err != nil {
				t.Fatal(err)
			}
			var variants = []corpus.Fixture{f, split}
			coalesced, err := corpus.Apply(f, corpus.Coalesce(32768))
			if err != nil {
				t.Fatal(err)
			}
			variants = append(variants, coalesced)
			reordered, err := corpus.Apply(split, corpus.Reorder(2, []int{1, 0}))
			if err != nil {
				t.Fatal(err)
			}
			variants = append(variants, reordered)
			index := -1
			for i, p := range split.Packets {
				if len(p.Decoded.Payload) > 0 && p.Decoded.TCP.Flags&7 == 0 {
					index = i
					break
				}
			}
			if index < 0 {
				t.Fatal("capture has no data for retransmit")
			}
			retransmitted, err := corpus.Apply(split, corpus.Retransmit([]int{index}))
			if err != nil {
				t.Fatal(err)
			}
			variants = append(variants, retransmitted)
			for i, variant := range variants {
				for _, position := range []corpus.PositionMode{corpus.Sequence, corpus.SessionOffsets} {
					t.Run(fmt.Sprintf("variant%d/mode%d", i, position), func(t *testing.T) {
						got := replayCapture(t, variant, position)
						if !reflect.DeepEqual(got, baseline) {
							t.Fatalf("ordered per-direction trace changed:\n%+v\nbaseline:\n%+v", got, baseline)
						}
					})
				}
			}
		})
	}
}
