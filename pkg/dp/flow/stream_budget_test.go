// SPDX-License-Identifier: Apache-2.0
package flow

import (
	"errors"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestByteStreamInspectionAdmission(t *testing.T) {
	r := limits.NewResources(limits.NewBudget(1), nil)
	b, err := NewBudgetedByteStream(64, 4, r, true)
	if b != nil || !errors.Is(err, ErrInspectionLimit) || r.Budget.Status().InUse != 0 {
		t.Fatalf("refused admission = %v, %v, %+v", b, err, r.Budget.Status())
	}
}

func TestByteStreamInspectionReplacementPeak(t *testing.T) {
	for _, path := range []string{"history", "out_of_order", "drain", "ack"} {
		t.Run(path, func(t *testing.T) {
			r := limits.NewResources(limits.NewBudget(8192), nil)
			b, err := NewBudgetedByteStream(64, 4, r, true)
			if err != nil {
				t.Fatal(err)
			}
			setup := func(off int64, data string) {
				t.Helper()
				if _, _, err := b.Add(off, []byte(data)); err != nil {
					t.Fatal(err)
				}
			}
			switch path {
			case "history", "ack":
				setup(0, "abcdefgh")
			case "drain":
				setup(0, "ab")
				setup(4, "efgh")
			}
			used, next, buffered := r.Budget.Status().InUse, b.Next(), b.Buffered()
			room := int64(3)
			if path == "history" {
				room = 9 // the 10-byte replacement must coexist with 8 old bytes
			} else if path == "drain" {
				room = 7 // full 8-byte replacement, not just the bridge
			}
			blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 8192-used-room)
			if !ok {
				t.Fatal("blocker")
			}
			switch path {
			case "history":
				_, _, err = b.Add(8, []byte("ij"))
			case "out_of_order":
				_, _, err = b.Add(4, []byte("efgh"))
			case "drain":
				_, _, err = b.Add(2, []byte("cd"))
			case "ack":
				err = b.Ack(4)
			}
			if !errors.Is(err, ErrInspectionLimit) || b.Next() != next || b.Buffered() != buffered {
				t.Fatalf("refusal changed the stream: %v next=%d buffered=%d", err, b.Next(), b.Buffered())
			}
			blocker.Release()
			if r.Budget.Status().InUse != used {
				t.Fatal("refusal leaked")
			}
			if path == "ack" {
				if err := b.Ack(4); err != nil {
					t.Fatal(err)
				}
				if r.Budget.Status().InUse != used-4 {
					t.Fatal("ack replacement retained old backing")
				}
			}
			b.Release()
			b.Release()
			if r.Budget.Status().InUse != 0 {
				t.Fatal("teardown leaked")
			}
		})
	}
}
