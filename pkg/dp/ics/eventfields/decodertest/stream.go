// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package decodertest

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// CheckStream is for stateless decoders. Stateful callers must use
// CheckStreamFactory, which isolates the prefix replay.
// CheckStream runs sd.ParseStream on an owned copy of v and fails t unless
// the result keeps the dpi.StreamDecoder contract:
//   - frames are contiguous from v.Base, in order, non-empty, inside the view;
//   - Consumed is exactly the complete-frame prefix;
//   - the only error is a *dpi.FrameError at the end of that prefix, and its
//     event is malformed;
//   - NeedMore is set exactly when an error-free parse leaves a tail;
//   - the result does not change when the view's bytes are overwritten
//     afterwards (no reference kept);
//   - reparsing exactly the consumed prefix yields the same frames and
//     nothing else.
func CheckStream(t testing.TB, sd dpi.StreamDecoder, state *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	t.Helper()
	return checkStream(t, sd, state, v, func() dpi.StreamDecoder { return sd })
}

// CheckStreamFactory checks one parse and its prefix replay with separate fresh
// decoders. makeDecoder must construct new state, not return a shared instance.
func CheckStreamFactory(t testing.TB, makeDecoder func() dpi.StreamDecoder, state *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	t.Helper()
	ownedState := cloneState(state)
	return checkStream(t, makeDecoder(), ownedState, v, makeDecoder)
}

func checkStream(t testing.TB, sd dpi.StreamDecoder, state *flow.State, v dpi.StreamView, reparse func() dpi.StreamDecoder) (dpi.StreamResult, error) {
	t.Helper()
	prefixState := cloneState(state)
	view := v
	view.Bytes = append([]byte(nil), v.Bytes...)
	res, err := sd.ParseStream(state, view)
	pos := v.Base
	for i, f := range res.Frames {
		if f.Start != pos || f.End <= f.Start || f.End > v.Base+int64(len(v.Bytes)) {
			t.Fatalf("frame %d [%d,%d): want start %d inside [%d,%d]", i, f.Start, f.End, pos, v.Base, v.Base+int64(len(v.Bytes)))
		}
		pos = f.End
	}
	if int64(res.Consumed) != pos-v.Base {
		t.Fatalf("Consumed %d, frames end at %d (base %d)", res.Consumed, pos, v.Base)
	}
	if err != nil {
		var fe *dpi.FrameError
		if !errors.As(err, &fe) {
			t.Fatalf("error %T %v is not a *dpi.FrameError", err, err)
		}
		if fe.Offset != pos || fe.Event.Kind != "malformed" || fe.Event.Proto != sd.Protocol() {
			t.Fatalf("FrameError at %d (frames end %d), event %s/%s", fe.Offset, pos, fe.Event.Proto, fe.Event.Kind)
		}
	} else if res.NeedMore != (res.Consumed < len(v.Bytes)) {
		t.Fatalf("NeedMore %v with %d of %d bytes consumed", res.NeedMore, res.Consumed, len(v.Bytes))
	}
	before := describe(res, err, true)
	for i := range view.Bytes {
		view.Bytes[i] = 0xEE
	}
	if after := describe(res, err, true); after != before {
		t.Fatalf("result changed when the view was overwritten:\n%s\n%s", before, after)
	}
	if res.Consumed > 0 && reparse != nil {
		prefix := v
		prefix.Bytes = append([]byte(nil), v.Bytes[:res.Consumed]...)
		again, againErr := reparse().ParseStream(prefixState, prefix)
		if againErr != nil || again.NeedMore || Describe(again, nil) != Describe(dpi.StreamResult{Frames: res.Frames, Consumed: res.Consumed}, nil) {
			t.Fatalf("reparsing the consumed prefix: err %v needMore %v\n%s\nwant\n%s", againErr, again.NeedMore, Describe(again, nil), Describe(res, nil))
		}
	}
	return res, err
}

// CheckSplits is for stateless decoders; stateful callers use CheckSplitsFactory.
// CheckSplits delivers v in two parts at every cut point, the way the DPI
// manager does: the second view starts where the first parse's consumed
// prefix ends. Every split must give the frames, events and error of the
// unsplit parse, and the first part must never decode a frame that ends
// beyond the cut.
func CheckSplits(t testing.TB, sd dpi.StreamDecoder, state *flow.State, v dpi.StreamView) {
	t.Helper()
	checkSplits(t, func() dpi.StreamDecoder { return sd }, state, v, false)
}

// CheckSplitsFactory uses a fresh decoder for the whole parse, prefix reparse,
// and each split schedule. The head and tail of a schedule share one decoder:
// they are successive views of one stream, not independent replays.
func CheckSplitsFactory(t testing.TB, makeDecoder func() dpi.StreamDecoder, state *flow.State, v dpi.StreamView) {
	t.Helper()
	checkSplits(t, makeDecoder, state, v, true)
}

func checkSplits(t testing.TB, makeDecoder func() dpi.StreamDecoder, state *flow.State, v dpi.StreamView, fresh bool) {
	t.Helper()
	wholeState := state
	if fresh {
		wholeState = cloneState(state)
	}
	whole, wholeErr := checkStream(t, makeDecoder(), wholeState, v, makeDecoder)
	want := Describe(whole, wholeErr)
	for cut := 1; cut < len(v.Bytes); cut++ {
		sd := makeDecoder()
		splitState := state
		var reparse func() dpi.StreamDecoder
		if fresh {
			splitState = cloneState(state)
		} else {
			reparse = makeDecoder
		}
		head := v
		head.Bytes = v.Bytes[:cut]
		first, err := checkStream(t, sd, splitState, head, reparse)
		if err != nil {
			if got := Describe(first, err); got != want {
				t.Fatalf("cut %d: early error\n%s\nwant\n%s", cut, got, want)
			}
			continue
		}
		tail := v
		tail.Base = v.Base + int64(first.Consumed)
		tail.Bytes = v.Bytes[first.Consumed:]
		second, err := checkStream(t, sd, splitState, tail, reparse)
		joined := dpi.StreamResult{Frames: append(append([]dpi.DecodedFrame(nil), first.Frames...), second.Frames...), Consumed: first.Consumed + second.Consumed, NeedMore: second.NeedMore}
		if got := Describe(joined, err); got != want {
			t.Fatalf("cut %d:\n%s\nwant\n%s", cut, got, want)
		}
	}
}

func cloneState(state *flow.State) *flow.State {
	if state == nil {
		return nil
	}
	owned := *state
	owned.Key.SrcIP = append([]byte(nil), state.Key.SrcIP...)
	owned.Key.DstIP = append([]byte(nil), state.Key.DstIP...)
	owned.Tags = append([]string(nil), state.Tags...)
	return &owned
}

// Describe renders a parse result without timestamps, for comparisons. A
// FrameError is rendered by offset, reason and event kind: its event's bytes
// depend on how much of the stream the view held.
func Describe(res dpi.StreamResult, err error) string {
	return describe(res, err, false)
}

func describe(res dpi.StreamResult, err error, errorEvent bool) string {
	var b strings.Builder
	for _, f := range res.Frames {
		fmt.Fprintf(&b, "[%d,%d)\n", f.Start, f.End)
		for _, ev := range f.Events {
			fmt.Fprintf(&b, "  %s/%s %v\n", ev.Proto, ev.Kind, ev.Attributes)
		}
	}
	fmt.Fprintf(&b, "consumed=%d needMore=%v\n", res.Consumed, res.NeedMore)
	var fe *dpi.FrameError
	if errors.As(err, &fe) {
		fmt.Fprintf(&b, "error at %d: %s (%s/%s)\n", fe.Offset, fe.Reason, fe.Event.Proto, fe.Event.Kind)
		if errorEvent {
			fmt.Fprintf(&b, "  %v\n", fe.Event.Attributes)
		}
	} else if err != nil {
		fmt.Fprintf(&b, "error: %v\n", err)
	}
	return b.String()
}
