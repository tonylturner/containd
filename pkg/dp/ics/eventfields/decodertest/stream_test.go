// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package decodertest

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// The event count depends on prior complete frames, exposing decoder reuse.
type countingDecoder struct{ count int }

func (*countingDecoder) Protocol() string          { return "fake" }
func (*countingDecoder) Supports(*flow.State) bool { return true }
func (*countingDecoder) OnPacket(*flow.State, *dpi.ParsedPacket) ([]dpi.Event, error) {
	return nil, nil
}
func (*countingDecoder) OnFlowEnd(*flow.State) ([]dpi.Event, error) { return nil, nil }
func (d *countingDecoder) ParseStream(state *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	var r dpi.StreamResult
	for i := 0; i+2 <= len(v.Bytes); i += 2 {
		d.count++
		state.Packets++
		r.Frames = append(r.Frames, dpi.DecodedFrame{Start: v.Base + int64(i), End: v.Base + int64(i+2), Events: []dpi.Event{{Proto: "fake", Kind: "frame", Attributes: map[string]any{"ordinal": d.count, "flowOrdinal": state.Packets}}}})
		r.Consumed += 2
	}
	r.NeedMore = r.Consumed < len(v.Bytes)
	return r, nil
}
func TestFreshFactory(t *testing.T) {
	made := 0
	factory := func() dpi.StreamDecoder { made++; return &countingDecoder{} }
	state := &flow.State{}
	v := dpi.StreamView{Session: "stateful", Base: 10, Bytes: []byte{1, 2, 3, 4, 5}}
	CheckStreamFactory(t, factory, state, v)
	if made != 2 {
		t.Fatalf("constructed %d, want separate full and prefix decoders", made)
	}
	made = 0
	CheckSplitsFactory(t, factory, state, v)
	if state.Packets != 0 {
		t.Fatal("factory replay mutated caller flow state")
	}
	if made != 6 {
		t.Fatalf("constructed %d, want 2 + 4 split schedules", made)
	}
}
