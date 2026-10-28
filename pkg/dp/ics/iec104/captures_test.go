// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package iec104

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
)

type captureLabel struct {
	Frame  int    `json:"frame"`
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Offset *int64 `json:"offset,omitempty"`
}

type captureExpectations struct {
	Class  string         `json:"class"`
	Labels []captureLabel `json:"labels"`
}

type captureRange struct {
	start, end int64
	frame      int
}

type captureRun struct {
	steps     []corpus.Step
	semantics map[string][]string
	byFrame   map[int][]dpi.DecodedFrame
}

type captureStreamSeed struct {
	bytes []byte
	dir   dpi.StreamDir
}

func loadReferenceCaptures(tb testing.TB) []corpus.Fixture {
	tb.Helper()
	fixtures, err := corpus.Load(os.DirFS("../../../../"), "test/iec104/testdata/manifest.json")
	if err != nil {
		tb.Fatal(err)
	}
	if len(fixtures) != 5 {
		tb.Fatalf("expected five reference captures, got %d", len(fixtures))
	}
	for _, fixture := range fixtures {
		if fixture.Manifest.Protocol != "iec104" || fixture.Spec.Transport != "tcp" ||
			len(fixture.Spec.Roles) != 0 || !fixture.Spec.Contiguous {
			tb.Fatalf("%s is not a handshake-oriented contiguous IEC104 fixture", fixture.Name)
		}
	}
	return fixtures
}

func captureStreamSeeds(tb testing.TB, fixture corpus.Fixture) []captureStreamSeed {
	tb.Helper()
	directions := make(map[string]dpi.StreamDir)
	var order []string
	for _, packet := range fixture.Packets {
		if len(packet.Decoded.Payload) == 0 {
			continue
		}
		key := captureStreamKey(packet.Connection, packet.Dir)
		if _, exists := directions[key]; !exists {
			directions[key] = packet.Dir
			order = append(order, key)
		}
	}
	streams, err := corpus.StreamSeeds(fixture)
	if err != nil {
		tb.Fatalf("%s stream seeds: %v", fixture.Name, err)
	}
	if len(streams) != len(order) {
		tb.Fatalf("%s yielded %d stream seeds for %d directions", fixture.Name, len(streams), len(order))
	}
	out := make([]captureStreamSeed, len(streams))
	for i, key := range order {
		out[i] = captureStreamSeed{bytes: streams[i], dir: directions[key]}
	}
	return out
}

func captureStreamKey(connection string, dir dpi.StreamDir) string {
	return fmt.Sprintf("%s/%d", connection, dir)
}

func replayReferenceCapture(tb *testing.T, fixture corpus.Fixture, mode corpus.PositionMode) captureRun {
	tb.Helper()
	steps, err := corpus.Replay(func() *dpi.Manager {
		return dpi.NewManager(NewDecoder())
	}, fixture, corpus.ReplayOptions{
		Position:          mode,
		FailClosed:        true,
		SimulateHandshake: true,
	})
	if err != nil {
		tb.Fatal(err)
	}

	ranges := make(map[string][]captureRange)
	for _, packet := range fixture.Packets {
		if len(packet.Decoded.Payload) == 0 {
			continue
		}
		if !packet.HasOrigin || !packet.Decoded.TCP.Valid {
			tb.Fatalf("%s frame %d has no TCP origin", fixture.Name, packet.Source[0].Frame)
		}
		seq := packet.Decoded.TCP.Seq
		if packet.Decoded.TCP.Flags&capture.TCPFlagSYN != 0 {
			seq++
		}
		start := int64(int32(seq - packet.Origin))
		offset := 0
		key := captureStreamKey(packet.Connection, packet.Dir)
		for _, source := range packet.Source {
			n := source.End - source.Start
			if n == 0 {
				continue
			}
			ranges[key] = append(ranges[key], captureRange{
				start: start + int64(offset),
				end:   start + int64(offset+n),
				frame: source.Frame,
			})
			offset += n
		}
		if offset != len(packet.Decoded.Payload) {
			tb.Fatalf("%s frame %d source spans cover %d of %d payload bytes",
				fixture.Name, packet.Source[0].Frame, offset, len(packet.Decoded.Payload))
		}
	}

	owner := func(key string, offset int64) int {
		var frame int
		for _, r := range ranges[key] {
			if offset < r.start || offset >= r.end {
				continue
			}
			if frame != 0 && frame != r.frame {
				tb.Fatalf("%s stream offset %d has conflicting source frames %d and %d", key, offset, frame, r.frame)
			}
			frame = r.frame
		}
		if frame == 0 {
			tb.Fatalf("%s stream offset %d has no capture source", key, offset)
		}
		return frame
	}

	run := captureRun{
		steps:     steps,
		semantics: make(map[string][]string),
		byFrame:   make(map[int][]dpi.DecodedFrame),
	}
	for _, step := range steps {
		for _, frame := range step.Result.Frames {
			key := captureStreamKey(step.Packet.Connection, step.Packet.Dir)
			sourceFrame := owner(key, frame.End-1)
			run.byFrame[sourceFrame] = append(run.byFrame[sourceFrame], frame)
			for _, event := range frame.Events {
				checkCaptureEvent(tb, event, false)
				run.semantics[key] = append(run.semantics[key], captureSemantic(tb, event))
			}
		}
		if len(step.Result.Events) < eventCount(step.Result.Frames) {
			tb.Fatalf("%s %s returned fewer events than decoded frames", fixture.Name, step.Kind)
		}
		for _, event := range step.Result.Events[eventCount(step.Result.Frames):] {
			var frameError *dpi.FrameError
			checkCaptureEvent(tb, event, errors.As(step.Result.Err, &frameError))
			key := captureStreamKey(step.Packet.Connection, step.Packet.Dir)
			run.semantics[key] = append(run.semantics[key], captureSemantic(tb, event))
		}
	}
	return run
}

func eventCount(frames []dpi.DecodedFrame) int {
	count := 0
	for _, frame := range frames {
		count += len(frame.Events)
	}
	return count
}

func checkCaptureEvent(tb *testing.T, event dpi.Event, frameError bool) {
	tb.Helper()
	if !validKinds[event.Kind] || event.Proto != eventfields.ProtoIEC104 {
		tb.Fatalf("unexpected event %s/%s", event.Proto, event.Kind)
	}
	if _, ok := event.Attributes[eventfields.KeyAPDUID]; !ok {
		tb.Fatalf("event without apdu_id: %v", event.Attributes)
	}
	_, hasErr := event.Attributes[eventfields.KeyError]
	if hasErr != (event.Kind == eventfields.KindMalformed || event.Kind == eventfields.KindUnsupported) {
		tb.Fatalf("%s event error presence %v", event.Kind, hasErr)
	}
	if frameError {
		if _, present := event.Attributes[eventfields.KeyConformance]; present {
			tb.Fatalf("FrameError carries conformance findings: %v", event.Attributes)
		}
	} else {
		checkFindings(tb, event)
	}
	if _, err := json.Marshal(event.Attributes); err != nil {
		tb.Fatalf("attributes do not marshal: %v", err)
	}
}

func captureSemantic(tb *testing.T, event dpi.Event) string {
	tb.Helper()
	attributes := make(map[string]any, len(event.Attributes))
	for key, value := range event.Attributes {
		if key == eventfields.KeyAPDUID || key == eventfields.KeySessionID {
			continue
		}
		attributes[key] = value
	}
	encoded, err := json.Marshal(attributes)
	if err != nil {
		tb.Fatal(err)
	}
	return event.Proto + "/" + event.Kind + "/" + string(encoded)
}

func readCaptureExpectations(tb testing.TB, fixture corpus.Fixture) captureExpectations {
	tb.Helper()
	var out captureExpectations
	if err := json.Unmarshal(fixture.Expectations["class"], &out.Class); err != nil {
		tb.Fatalf("%s expectation class: %v", fixture.Name, err)
	}
	if err := json.Unmarshal(fixture.Expectations["labels"], &out.Labels); err != nil {
		tb.Fatalf("%s expectation labels: %v", fixture.Name, err)
	}
	if out.Class == "" {
		tb.Fatalf("%s has no expectation class", fixture.Name)
	}
	return out
}

func assertReplayErrors(tb *testing.T, fixture corpus.Fixture, run captureRun, expected captureExpectations) {
	tb.Helper()
	frameErrors := make(map[string]captureLabel)
	frameErrorLabels := make(map[int]captureLabel)
	seenInitial := make(map[int]bool)
	for _, label := range expected.Labels {
		if label.Kind == "frame_error" {
			frameErrorLabels[label.Frame] = label
			for _, packet := range fixture.Packets {
				if sourceFrame(packet) == label.Frame {
					frameErrors[captureStreamKey(packet.Connection, packet.Dir)] = label
					break
				}
			}
		}
	}
	for _, step := range run.steps {
		if step.Result.Err == nil {
			continue
		}
		frame := 0
		if len(step.Packet.Source) > 0 {
			frame = step.Packet.Source[0].Frame
		}
		key := captureStreamKey(step.Packet.Connection, step.Packet.Dir)
		label, ok := frameErrors[key]
		var frameErr *dpi.FrameError
		if step.Kind != "inspect" || !ok || !errors.As(step.Result.Err, &frameErr) {
			tb.Fatalf("%s unexpected %s error at source frame %d: %v", fixture.Name, step.Kind, frame, step.Result.Err)
		}
		if label.Offset == nil || frameErr.Offset != *label.Offset {
			tb.Fatalf("%s frame %d error offset %d, want %v", fixture.Name, frame, frameErr.Offset, label.Offset)
		}
		if frame == label.Frame {
			seenInitial[frame] = true
		}
	}
	for frame := range frameErrorLabels {
		if !seenInitial[frame] {
			tb.Fatalf("%s did not observe labelled frame error at source frame %d", fixture.Name, frame)
		}
	}
}

func assertCaptureExpectations(tb *testing.T, fixture corpus.Fixture, run captureRun, expected captureExpectations) {
	tb.Helper()
	assertReplayErrors(tb, fixture, run, expected)
	for _, label := range expected.Labels {
		switch label.Kind {
		case "frame_error":
			if len(run.byFrame[label.Frame]) != 0 {
				tb.Fatalf("%s frame %d malformed frame error was reported as a decoded APDU", fixture.Name, label.Frame)
			}
		case "incomplete":
			found := false
			for _, step := range run.steps {
				if step.Kind == "inspect" && sourceFrame(step.Packet) == label.Frame {
					if step.Result.Err != nil || !step.Result.NeedMore || len(step.Result.Events) != 0 {
						tb.Fatalf("%s frame %d incomplete APDU result: %+v", fixture.Name, label.Frame, step.Result)
					}
					found = true
				}
			}
			if !found {
				tb.Fatalf("%s missing incomplete source frame %d", fixture.Name, label.Frame)
			}
		case "malformed", "unsupported":
			frames := run.byFrame[label.Frame]
			var events []dpi.Event
			for _, frame := range frames {
				events = append(events, frame.Events...)
			}
			if len(events) != 1 || events[0].Kind != label.Kind {
				tb.Fatalf("%s frame %d (%s): got %v", fixture.Name, label.Frame, label.Label, events)
			}
		default:
			tb.Fatalf("%s has unknown expectation kind %q", fixture.Name, label.Kind)
		}
	}
}

func sourceFrame(packet corpus.Packet) int {
	if len(packet.Source) == 0 {
		return 0
	}
	return packet.Source[0].Frame
}

func assertCaptureOracle(tb *testing.T, fixture corpus.Fixture, run captureRun, expected captureExpectations) {
	tb.Helper()
	labels := make(map[int]string)
	for _, label := range expected.Labels {
		labels[label.Frame] = label.Kind
	}
	for _, row := range fixture.Oracle {
		frames := run.byFrame[row.Frame]
		if len(frames) == 0 {
			tb.Fatalf("%s oracle frame %d produced no decoded APDU", fixture.Name, row.Frame)
		}
		badObjects := labels[row.Frame] == "malformed" || labels[row.Frame] == "unsupported"
		checkCaptureOracle(tb, dpi.StreamResult{Frames: frames}, row.Fields, badObjects)
	}
	for _, frame := range fixture.Spec.UnobservedFrames {
		if len(run.byFrame[frame]) != 0 {
			tb.Fatalf("%s unobserved payload frame %d produced a complete APDU", fixture.Name, frame)
		}
	}
}

func TestReferenceCaptureManagerReplay(t *testing.T) {
	fixtures := loadReferenceCaptures(t)
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			expected := readCaptureExpectations(t, fixture)
			var baseline map[string][]string
			for _, mode := range []corpus.PositionMode{corpus.Sequence, corpus.SessionOffsets} {
				run := replayReferenceCapture(t, fixture, mode)
				assertCaptureOracle(t, fixture, run, expected)
				assertCaptureExpectations(t, fixture, run, expected)
				if baseline == nil {
					baseline = run.semantics
				} else if !reflect.DeepEqual(run.semantics, baseline) {
					t.Fatal("sequence and session-offset replay semantics differ")
				}
			}

			firstData := -1
			for i, packet := range fixture.Packets {
				if len(packet.Decoded.Payload) > 0 &&
					packet.Decoded.TCP.Flags&^(capture.TCPFlagACK|capture.TCPFlagPSH) == 0 {
					firstData = i
					break
				}
			}
			if firstData < 0 {
				t.Fatal("fixture has no retransmittable data segment")
			}
			transforms := []struct {
				name      string
				transform corpus.Transform
			}{
				{"split", corpus.Split(7)},
				{"coalesce", corpus.Coalesce(32768)},
				{"reorder", corpus.Reorder(2, []int{1, 0})},
				{"retransmit", corpus.Retransmit([]int{firstData})},
			}
			for _, tc := range transforms {
				t.Run(tc.name, func(t *testing.T) {
					derived, err := corpus.Apply(fixture, tc.transform)
					if err != nil {
						t.Fatal(err)
					}
					if len(derived.Derived) == 0 {
						t.Fatal("transform did not mark a derived fixture")
					}
					for _, mode := range []corpus.PositionMode{corpus.Sequence, corpus.SessionOffsets} {
						run := replayReferenceCapture(t, derived, mode)
						assertReplayErrors(t, derived, run, expected)
						if !reflect.DeepEqual(run.semantics, baseline) {
							t.Fatalf("%s replay semantics differ from original", tc.name)
						}
					}
				})
			}
		})
	}
}
