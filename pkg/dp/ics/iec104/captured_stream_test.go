// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package iec104

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func TestReferenceCapturePackets(t *testing.T) {
	for _, ref := range loadReferenceCaptures(t) {
		t.Run(ref.name, func(t *testing.T) {
			seen := make(map[int]bool)
			for _, s := range ref.streams {
				var pending []byte
				var base int64
				for _, seg := range s.segments {
					if !t.Run(fmt.Sprintf("frame-%d", seg.frame), func(t *testing.T) {
						pending = append(pending, seg.bytes...)
						res, err := decodertest.CheckStream(t, NewDecoder(), iecState(), view(s.dir, base, pending))
						checkEvents(t, res)
						// Wireshark does not flag these strictness failures.
						wantKind := ""
						if ref.name == "malformed.pcap" {
							switch seg.frame {
							case 16:
								var fe *dpi.FrameError
								if !errors.As(err, &fe) || fe.Offset != 6 {
									t.Fatalf("bad length: got %v, want FrameError at 6", err)
								}
								pending = nil
								return
							case 28, 29:
								wantKind = "malformed"
							case 37:
								wantKind = "unsupported"
							}
						}
						if err != nil {
							t.Fatal(err)
						}
						if wantKind != "" && len(events(res)) != 1 {
							t.Fatalf("%s APDU: got %d events, want one", wantKind, len(events(res)))
						}
						for _, ev := range events(res) {
							if wantKind != "" && ev.Kind != wantKind ||
								wantKind == "" && ev.Kind != "request" && ev.Kind != "response" && ev.Kind != "apci" {
								t.Fatalf("unexpected event kind %s (strictness override %q)", ev.Kind, wantKind)
							}
						}
						row := ref.oracle[seg.frame]
						if row == nil {
							if len(res.Frames) != 0 || !res.NeedMore {
								t.Fatalf("no oracle row, but got %d frames, needMore %v", len(res.Frames), res.NeedMore)
							}
						} else {
							seen[seg.frame] = true
							if hex.EncodeToString(seg.bytes) != row["tcp.payload"] {
								t.Fatal("oracle payload differs from capture")
							}
							if server := row["tcp.srcport"] == "2404"; server != (s.dir == dpi.ServerToClient) {
								t.Fatal("oracle direction differs from capture")
							}
							checkCaptureOracle(t, res, row, wantKind != "")
						}
						pending = pending[res.Consumed:]
						base += int64(res.Consumed)
					}) {
						t.FailNow()
					}
				}
				if len(pending) > 0 && !(ref.name == "malformed.pcap" && s.segments[0].frame == 4) {
					t.Fatalf("%s: unexpected incomplete stream tail", s.name)
				}
			}
			if len(seen) != len(ref.oracle) {
				t.Fatalf("checked %d of %d oracle rows", len(seen), len(ref.oracle))
			}
		})
	}
}

func TestReferenceCaptureStreamTransforms(t *testing.T) {
	for _, ref := range loadReferenceCaptures(t) {
		for _, s := range ref.streams {
			t.Run(s.name, func(t *testing.T) {
				// Coalescing is per connection AND direction, never across
				// unrelated clients. Includes captured errors and partial tails.
				v := view(s.dir, 0, s.bytes)
				decodertest.CheckSplits(t, NewDecoder(), iecState(), v)
				whole, err := decodertest.CheckStream(t, NewDecoder(), iecState(), v)
				checkEvents(t, whole)
				if err != nil || whole.NeedMore {
					return // Already a captured invalid or incomplete tail.
				}
				// Deterministic complete-prefix + partial-next-APDU transforms,
				// using captured bytes, not synthetic framing.
				for _, frame := range whole.Frames {
					for tail := frame.Start + 1; tail < frame.End; tail++ {
						v.Bytes = s.bytes[:tail]
						res, err := decodertest.CheckStream(t, NewDecoder(), iecState(), v)
						if err != nil || !res.NeedMore || int64(res.Consumed) != frame.Start {
							t.Fatalf("tail at %d: consumed %d needMore %v err %v", tail, res.Consumed, res.NeedMore, err)
						}
						checkEvents(t, res)
					}
				}
			})
		}
	}
}
