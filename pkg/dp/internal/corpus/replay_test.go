// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

type fakeDecoder struct {
	ended    []string
	flowEnds int
	parses   int
}

func (*fakeDecoder) Supports(*flow.State) bool { return true }
func (*fakeDecoder) Protocol() string          { return "fake" }
func (d *fakeDecoder) OnPacket(_ *flow.State, p *dpi.ParsedPacket) ([]dpi.Event, error) {
	return []dpi.Event{{Proto: "fake", Kind: string(p.Payload)}}, nil
}
func (d *fakeDecoder) OnFlowEnd(s *flow.State) ([]dpi.Event, error) {
	d.flowEnds++
	return []dpi.Event{{Proto: "fake", Kind: "end", Attributes: map[string]any{"packets": s.Packets}}}, nil
}
func (d *fakeDecoder) StreamEnded(session string, dir dpi.StreamDir) {
	d.ended = append(d.ended, fmt.Sprintf("%s/%d", session, dir))
}
func (d *fakeDecoder) ParseStream(_ *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	d.parses++
	var r dpi.StreamResult
	for i := 0; i+2 <= len(v.Bytes); i += 2 {
		r.Frames = append(r.Frames, dpi.DecodedFrame{Start: v.Base + int64(i), End: v.Base + int64(i+2), Events: []dpi.Event{{Proto: "fake", Kind: string(v.Bytes[i : i+2])}}})
		r.Consumed += 2
	}
	r.NeedMore = r.Consumed < len(v.Bytes)
	return r, nil
}
func fixture(t *testing.T, records ...[]byte) Fixture {
	t.Helper()
	f := Fixture{Name: "fake", Spec: Scenario{Contiguous: true}, Packets: readPackets(t, records...)}
	if err := orient(&f); err != nil {
		t.Fatal(err)
	}
	return f
}
func kinds(steps []Step) []string {
	var out []string
	for _, s := range steps {
		if s.Kind == "inspect" {
			for _, e := range s.Result.Events {
				out = append(out, e.Kind)
			}
		}
	}
	return out
}
func TestReplayPositionsFreshAndGaps(t *testing.T) {
	// ISN wraps to zero. Data is reordered, then duplicated after consumption.
	f := fixture(t, wire(6, ^uint32(0), capture.TCPFlagSYN, "", false), wire(6, 2, capture.TCPFlagACK, "cd", false), wire(6, 0, capture.TCPFlagACK, "ab", false), wire(6, 0, capture.TCPFlagACK, "ab", false))
	made := 0
	for _, mode := range []PositionMode{Sequence, SessionOffsets} {
		d := &fakeDecoder{}
		steps, err := Replay(func() *dpi.Manager { made++; return dpi.NewManager(d) }, f, ReplayOptions{Position: mode, FailClosed: true, SimulateHandshake: true})
		if err != nil {
			t.Fatal(err)
		}
		if !steps[1].Result.Gap || len(steps[1].Result.Events) != 0 || !reflect.DeepEqual(kinds(steps), []string{"ab", "cd"}) {
			t.Fatalf("gap/duplicate behavior: %+v", steps)
		}
		if d.flowEnds != 1 || steps[len(steps)-1].Kind != "flow_end" {
			t.Fatalf("cleanup %+v", steps)
		}
		// StreamEnded dispatch is implemented by the Manager, not this helper.
	}
	if made != 2 {
		t.Fatalf("constructed %d Managers", made)
	}
}
func TestReplayConflictingOverlapAndIncompleteEOF(t *testing.T) {
	f := fixture(t, wire(6, 10, capture.TCPFlagSYN, "", false), wire(6, 11, capture.TCPFlagACK, "abc", false), wire(6, 13, capture.TCPFlagACK, "XY", false), wire(6, 15, capture.TCPFlagACK, "zz", false))
	for _, mode := range []PositionMode{Sequence, SessionOffsets} {
		d := &fakeDecoder{}
		steps, err := Replay(func() *dpi.Manager { return dpi.NewManager(d) }, f, ReplayOptions{Position: mode, FailClosed: true, SimulateHandshake: true})
		if err != nil {
			t.Fatal(err)
		}
		if !steps[1].Result.NeedMore || steps[2].Result.Err == nil || !steps[3].Result.Failed || d.flowEnds != 1 {
			t.Fatalf("overlap not preserved: %+v", steps)
		}
	}
	f.Packets = f.Packets[:2]
	d := &fakeDecoder{}
	steps, err := Replay(func() *dpi.Manager { return dpi.NewManager(d) }, f, ReplayOptions{})
	if err != nil || steps[1].Result.Err != nil || !steps[1].Result.NeedMore || d.flowEnds != 1 {
		t.Fatalf("EOF manufactured error: %v %+v", err, steps)
	}
}
func TestReplayBidirectionalCloseAndReuse(t *testing.T) {
	f := fixture(t,
		wire(6, 10, capture.TCPFlagSYN, "", false), wire(6, 90, capture.TCPFlagSYN|capture.TCPFlagACK, "", true),
		wire(6, 11, capture.TCPFlagACK, "ab", false), wire(6, 13, capture.TCPFlagFIN|capture.TCPFlagACK, "", false),
		wire(6, 91, capture.TCPFlagACK, "cd", true), wire(6, 93, capture.TCPFlagFIN|capture.TCPFlagACK, "", true),
		wire(6, 20, capture.TCPFlagSYN, "", false), wire(6, 21, capture.TCPFlagACK, "ef", false))
	if f.Packets[0].Connection == f.Packets[6].Connection || f.Packets[1].Dir != dpi.ServerToClient {
		t.Fatal("incarnation/direction lost")
	}
	for _, mode := range []PositionMode{Sequence, SessionOffsets} {
		steps, err := Replay(func() *dpi.Manager { return dpi.NewManager(&fakeDecoder{}) }, f, ReplayOptions{Position: mode, FailClosed: true, SimulateHandshake: true})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(kinds(steps), []string{"ab", "cd", "ef"}) {
			t.Fatalf("events: %v", kinds(steps))
		}
		if mode == SessionOffsets {
			inspections := 0
			ends := 0
			for _, s := range steps {
				if s.Kind == "inspect" {
					inspections++
				}
				if s.Kind == "end_session" {
					ends++
					if ends == 1 && inspections != 6 {
						t.Fatal("ended session on half-close")
					}
				}
			}
			if ends != 2 {
				t.Fatal("missing session cleanup")
			}
		}
	}
}
func TestReplayUDPAtomic(t *testing.T) {
	f := Fixture{Name: "udp", Spec: Scenario{Roles: []Role{{Transport: "udp", Client: "192.0.2.1:12345", Server: "192.0.2.2:2222"}}}, Packets: readPackets(t, wire(17, 0, 0, "ab", false), wire(17, 0, 0, "ab", false))}
	if err := orient(&f); err != nil {
		t.Fatal(err)
	}
	steps, err := Replay(func() *dpi.Manager { return dpi.NewManager(&fakeDecoder{}) }, f, ReplayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(kinds(steps), []string{"ab", "ab"}) {
		t.Fatal("deduplicated UDP")
	}
}
func TestReplayMetadataReject(t *testing.T) {
	f := fixture(t, wire(6, 1, capture.TCPFlagSYN, "", false), wire(6, 2, 0, "ab", false))
	for _, change := range []func(*Fixture){func(f *Fixture) { f.Packets[0].Connection = "" }, func(f *Fixture) { f.Packets[0].Dir = dpi.DirUnknown }, func(f *Fixture) { f.Packets[0].Decoded.TCP.Valid = false }, func(f *Fixture) { f.Packets[0].HasOrigin = false }} {
		copy := f
		copy.Packets = append([]Packet(nil), f.Packets...)
		change(&copy)
		called := false
		_, err := Replay(func() *dpi.Manager { called = true; return dpi.NewManager() }, copy, ReplayOptions{Position: SessionOffsets})
		if err == nil || called {
			t.Fatal("accepted metadata or allocated before validation")
		}
	}
}
func TestReplaySYNRetryMidstreamAndReplacement(t *testing.T) {
	f := fixture(t, wire(6, 10, capture.TCPFlagSYN, "", false), wire(6, 10, capture.TCPFlagSYN, "", false), wire(6, 11, 0, "ab", false), wire(6, 20, capture.TCPFlagSYN, "", false), wire(6, 21, 0, "cd", false))
	if f.Packets[0].Connection != f.Packets[1].Connection || f.Packets[0].Connection == f.Packets[3].Connection {
		t.Fatal("SYN retry or replacement identity")
	}
	f = Fixture{Name: "mid", Packets: readPackets(t, wire(6, 0, 0, "ab", false))}
	if err := orient(&f); err == nil {
		t.Fatal("silently guessed midstream role")
	}
	f.Spec.Roles = []Role{{Transport: "tcp", Client: "192.0.2.1:12345", Server: "192.0.2.2:502"}}
	if err := orient(&f); err == nil {
		t.Fatal("undeclared midstream")
	}
	f.Spec.AllowMidstream = true
	if err := orient(&f); err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(func() *dpi.Manager { return dpi.NewManager(&fakeDecoder{}) }, f, ReplayOptions{Position: SessionOffsets}); err == nil {
		t.Fatal("invented offset anchor")
	}
	steps, err := Replay(func() *dpi.Manager { return dpi.NewManager(&fakeDecoder{}) }, f, ReplayOptions{FailClosed: true})
	if err != nil || steps[0].Result.Err == nil {
		t.Fatal("lost fail-closed midstream error")
	}
}

func TestFreshReplayFactory(t *testing.T) {
	f := fixture(t, wire(6, 1, capture.TCPFlagSYN, "", false), wire(6, 2, 0, "abcd", false))
	split, err := Split(2).Apply(f)
	if err != nil {
		t.Fatal(err)
	}
	var decoders []*fakeDecoder
	factory := func() *dpi.Manager { d := &fakeDecoder{}; decoders = append(decoders, d); return dpi.NewManager(d) }
	for _, input := range []Fixture{f, split, f} {
		steps, err := Replay(factory, input, ReplayOptions{})
		if err != nil || !reflect.DeepEqual(kinds(steps), []string{"ab", "cd"}) {
			t.Fatalf("replay: %v %v", err, kinds(steps))
		}
	}
	if len(decoders) != 3 || decoders[0] == decoders[1] || decoders[0].parses != 1 || decoders[1].parses != 2 || decoders[2].parses != 1 {
		t.Fatal("constructor state not isolated")
	}
}

type endErrorDecoder struct{ fakeDecoder }

func (d *endErrorDecoder) OnFlowEnd(*flow.State) ([]dpi.Event, error) {
	d.flowEnds++
	return []dpi.Event{{Proto: "fake", Kind: "end-error"}}, fmt.Errorf("end observation")
}
func TestReplayLifecycleErrorsAndReset(t *testing.T) {
	f := fixture(t, wire(6, 1, capture.TCPFlagSYN, "", false), wire(6, 90, capture.TCPFlagSYN|capture.TCPFlagACK, "", true), wire(6, 2, 0, "ab", false), wire(6, 4, capture.TCPFlagRST, "", false))
	d := &endErrorDecoder{}
	steps, err := Replay(func() *dpi.Manager { return dpi.NewManager(&fakeDecoder{}, d) }, f, ReplayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	closeCount, resetCount, endCount := 0, 0, 0
	for _, s := range steps {
		if s.Kind == "inspect" {
			continue
		}
		if s.Result.Err == nil || len(s.Result.Events) != 2 || s.Result.Events[0].Kind != "end" || s.Result.Events[1].Kind != "end-error" {
			t.Fatalf("lost lifecycle error/events: %+v", s)
		}
		switch s.Kind {
		case "close":
			closeCount++
		case "reset":
			resetCount++
		case "flow_end":
			endCount++
		}
	}
	if closeCount != 1 || resetCount != 1 || endCount != 2 {
		t.Fatalf("close/reset/cleanup %d/%d/%d", closeCount, resetCount, endCount)
	}
}
