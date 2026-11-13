// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"math"
	"sync"
	"testing"
)

func TestBudgetHeadroomAndLease(t *testing.T) {
	b := NewBudget(100)
	l, ok := b.Reserve(ClassObserve, CategoryStream, 75)
	if !ok {
		t.Fatal("observe headroom")
	}
	if _, ok := b.Reserve(ClassObserve, CategoryStream, 1); ok {
		t.Fatal("observe stole headroom")
	}
	e, ok := b.Reserve(ClassEnforce, CategoryHeld, 25)
	if !ok {
		t.Fatal("enforcement headroom")
	}
	if l.Grow(1) || e.Grow(1) {
		t.Fatal("overshoot")
	}
	e.Shrink(10)
	if e.Size() != 15 || !e.Grow(10) {
		t.Fatal("shrink/grow")
	}
	e.Release()
	e.Release()
	l.Shrink(25)
	if !l.Grow(25) {
		t.Fatal("observe growth to ceiling")
	}
	s := b.Status()
	if o := b.LimitOccupancy(); o.Limit != 100 || o.ChargedBytes != 75 || o.HighWater != 100 {
		t.Fatalf("occupancy %+v", o)
	}
	if s.Limit != 100 || s.InUse != 75 || s.HighWater != 100 || s.ByCategory["stream"] != 75 || s.ByCategory["held"] != 0 {
		t.Fatalf("status: %+v", s)
	}
	l.Release()
	l.Shrink(1)
	if l.Grow(1) || l.Size() != 0 || b.Status().InUse != 0 {
		t.Fatal("released lease resurrected")
	}
}
func TestBudgetInvalidAndOverflow(t *testing.T) {
	for _, capacity := range []int64{-1, 0} {
		if _, ok := NewBudget(capacity).Reserve(ClassEnforce, CategoryStream, 1); ok {
			t.Fatal("invalid capacity")
		}
	}
	b := NewBudget(math.MaxInt64)
	for _, n := range []int64{math.MinInt64, -1, 0} {
		if _, ok := b.Reserve(ClassEnforce, CategoryStream, n); ok {
			t.Fatal("invalid size")
		}
	}
	if _, ok := b.Reserve(Class(255), CategoryStream, 1); ok {
		t.Fatal("invalid class")
	}
	if _, ok := b.Reserve(ClassEnforce, Category(255), 1); ok {
		t.Fatal("invalid category")
	}
	l, ok := b.Reserve(ClassEnforce, CategoryDecoder, math.MaxInt64)
	if !ok {
		t.Fatal("max capacity")
	}
	if l.Grow(1) || l.Grow(math.MaxInt64) || l.Grow(0) || l.Grow(-1) {
		t.Fatal("overflow or invalid growth")
	}
	l.Shrink(-1)
	l.Shrink(0)
	if l.Size() != math.MaxInt64 {
		t.Fatal("invalid shrink")
	}
	l.Release()
	small, _ := b.Reserve(ClassEnforce, CategoryPairing, 10)
	small.Shrink(11)
	if small.Size() != 10 {
		t.Fatal("excess shrink")
	}
	small.Shrink(10)
	if small.Size() != 0 || !small.Grow(1) {
		t.Fatal("zero-sized live lease")
	}
	small.Release()
	if s := b.Status(); s.InUse != 0 || s.ByCategory["decoder"] != 0 || s.ByCategory["pairing"] != 0 {
		t.Fatalf("refund: %+v", s)
	}
	for _, c := range []Category{CategoryStream, CategoryDecoder, CategoryHeld, CategoryPairing} {
		if c.String() == "unknown" {
			t.Fatal("category name")
		}
	}
	if Category(255).String() != "unknown" {
		t.Fatal("invalid category name")
	}
}
func TestBudgetFractionalHeadroom(t *testing.T) {
	for limit := int64(1); limit < 12; limit++ {
		b := NewBudget(limit)
		n := limit * 3 / 4
		if n > 0 {
			l, ok := b.Reserve(ClassObserve, CategoryStream, n)
			if !ok {
				t.Fatalf("limit %d", limit)
			}
			defer l.Release()
		}
		if _, ok := b.Reserve(ClassObserve, CategoryStream, 1); ok {
			t.Fatalf("fractional overshoot %d", limit)
		}
	}
}
func TestBudgetConcurrentReservations(t *testing.T) {
	b := NewBudget(64)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 500 {
				l, ok := b.Reserve(ClassEnforce, CategoryStream, 3)
				if ok {
					l.Grow(1)
					if s := b.Status(); s.InUse < 0 || s.InUse > s.Limit {
						t.Errorf("overshot: %+v", s)
					}
					l.Shrink(1)
					l.Release()
				}
			}
		})
	}
	wg.Wait()
	s := b.Status()
	if s.InUse != 0 || s.HighWater > 64 || s.ByCategory["stream"] != 0 {
		t.Fatalf("accounting: %+v", s)
	}
}
func TestLeaseConcurrentReleaseAndResize(t *testing.T) {
	b := NewBudget(1000)
	for range 100 {
		l, _ := b.Reserve(ClassEnforce, CategoryHeld, 100)
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for range 100 {
					l.Grow(1)
					l.Shrink(1)
					l.Size()
				}
				l.Release()
			})
		}
		for range 8 {
			wg.Go(l.Release)
		}
		wg.Wait()
		if l.Size() != 0 || l.Grow(1) || b.Status().InUse != 0 {
			t.Fatal("concurrent completion leaked or resurrected")
		}
	}
}
