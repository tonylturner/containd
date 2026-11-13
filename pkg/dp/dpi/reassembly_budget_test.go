// SPDX-License-Identifier: Apache-2.0
package dpi

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestReassemblyBudgetAdmission(t *testing.T) {
	r := newReassembler(64, time.Minute)
	setter, ok := any(r).(interface{ SetResources(limits.Resources) })
	if !ok {
		t.Fatal("reassembly does not accept shared resources")
	}
	resources := limits.NewResources(limits.NewBudget(512), nil)
	setter.SetResources(resources)
	res := r.feed("stream", position{}, []byte{1}, testNow, true, true, false)
	if res.err == nil || res.err.Kind.String() != "state_limit" {
		t.Fatalf("unbounded admission: %+v", res)
	}
	if len(r.streams) != 0 || resources.Budget.Status().InUse != 0 {
		t.Fatal("refused stream retained metadata")
	}
	r.fail("stream", &StreamError{Kind: StreamStateLimit})
	if len(r.streams) != 0 {
		t.Fatal("failure created an unadmitted stream")
	}
}

func TestReassemblyReplacementPeak(t *testing.T) {
	for _, path := range []string{"buffer", "history", "ooo", "absorb"} {
		t.Run(path, func(t *testing.T) {
			r := newReassembler(64, time.Minute)
			resources := limits.NewResources(limits.NewBudget(2048), nil)
			r.SetResources(resources)
			r.open("s", 100, testNow, true, true)
			res := feedVerify(r, "s", 100, true, 1, 2, 3, 4)
			if res.err != nil {
				t.Fatal(res.err)
			}
			switch path {
			case "buffer":
				r.trim("s", 0, 2)
			case "history":
				r.trim("s", 0, 2)
			case "ooo", "absorb":
				if got := feedVerify(r, "s", 106, true, 7, 8); got.err != nil {
					t.Fatal(got.err)
				}
			}
			used := resources.Budget.Status().InUse
			// Only two bytes are available: a net-growth-only charge would
			// incorrectly allow a three-byte replacement of a held allocation.
			blocker, ok := resources.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 2048-used-2)
			if !ok {
				t.Fatal("blocker")
			}
			var err *StreamError
			switch path {
			case "buffer":
				err = feedVerify(r, "s", 104, true, 5).err
			case "history":
				err = r.trim("s", 2, 1)
			case "ooo":
				err = feedVerify(r, "s", 105, true, 6, 7, 8).err
			case "absorb":
				err = feedVerify(r, "s", 104, true, 5, 6).err
			}
			if err == nil || err.Kind != StreamStateLimit {
				t.Fatalf("replacement did not charge its peak: %v", err)
			}
			if resources.Budget.Status().HighWater > 2048 {
				t.Fatal("budget exceeded")
			}
			r.fail("s", err)
			r.complete("s")
			blocker.Release()
			if resources.Budget.Status().InUse != 0 {
				t.Fatal("credit leak")
			}
		})
	}
}

func TestReassemblyBridgeDoesNotDoubleCountLocalBytes(t *testing.T) {
	r := newReassembler(8, time.Minute)
	r.feed("s", position{kind: posOffset}, []byte{1, 2, 3, 4}, testNow, true, true, false)
	r.feed("s", position{kind: posOffset, off: 6}, []byte{7, 8}, testNow, true, true, false)
	res := r.feed("s", position{kind: posOffset, off: 4}, []byte{5, 6, 7, 8}, testNow, true, true, false)
	if res.err != nil || len(res.buf) != 8 {
		t.Fatalf("overlapping bridge exceeded the logical local bound: %+v", res)
	}
}
