// SPDX-License-Identifier: Apache-2.0
package iec104

import (
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func TestRoleViolationEmitsEveryObject(t *testing.T) {
	for _, sq := range []bool{false, true} {
		count := byte(2)
		if sq {
			count = 127 // VSQ maximum, still within the APDU byte budget.
		}
		vsq := count
		var body []byte
		if sq {
			vsq |= vsqSQ
			body = ioa(100)
		}
		for i := byte(0); i < count; i++ {
			if !sq {
				body = append(body, ioa(100+uint32(i))...)
			}
			body = append(body, i&1)
		}
		raw := iFrame(0, 0, asdu(1, vsq, cotSpont|0xc0, 7, 42, body...))
		for _, dir := range []struct {
			direction dpi.StreamDir
			role      bool
		}{{cli, true}, {srv, false}} {
			evs := events(parseOne(t, dir.direction, raw))
			if len(evs) != int(count) {
				t.Fatalf("SQ=%v events=%d want=%d", sq, len(evs), count)
			}
			for i, ev := range evs {
				wantKind := eventfields.KindResponse
				if dir.role {
					wantKind = eventfields.KindMalformed
				}
				if ev.Kind != wantKind {
					t.Fatalf("object %d kind=%s want=%s", i, ev.Kind, wantKind)
				}
				for form, attrs := range decodertest.Forms(t, ev.Attributes) {
					codes, _ := eventfields.Strings(attrs, eventfields.KeyConformance)
					if slices.Contains(codes, FindingRole) != dir.role || (attrs[eventfields.KeyError] != nil) != dir.role {
						t.Fatalf("%s role finding lost: %v", form, attrs)
					}
					for key, want := range map[string]uint32{
						eventfields.KeyIOA: 100 + uint32(i), eventfields.KeyObjectIndex: uint32(i),
						eventfields.KeyObjectCount: uint32(count), eventfields.KeyCause: cotSpont,
						eventfields.KeyOriginator: 7, eventfields.KeyCA: 42, eventfields.KeyValue: uint32(i & 1),
					} {
						if got, ok := eventfields.Uint32(attrs, key); !ok || got != want {
							t.Fatalf("%s object %d %s=%v want=%v", form, i, key, attrs[key], want)
						}
					}
					for _, key := range []string{eventfields.KeyCOTNegative, eventfields.KeyCOTTest} {
						if got, _ := eventfields.Bool(attrs, key); !got {
							t.Fatalf("%s lost %s", form, key)
						}
					}
					if _, present := attrs[eventfields.KeyCoverageIncomplete]; present {
						t.Fatalf("%s fully decoded ASDU marked incomplete", form)
					}
				}
			}
		}
	}
}
