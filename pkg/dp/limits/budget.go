// SPDX-License-Identifier: Apache-2.0

package limits

import "sync/atomic"

type Class uint8

const (
	ClassEnforce Class = iota
	ClassObserve
)

type Category uint8

const (
	CategoryStream Category = iota
	CategoryDecoder
	CategoryHeld
	CategoryPairing
	categoryCount
)

func (c Category) String() string {
	switch c {
	case CategoryStream:
		return "stream"
	case CategoryDecoder:
		return "decoder"
	case CategoryHeld:
		return "held"
	case CategoryPairing:
		return "pairing"
	default:
		return "unknown"
	}
}

type BudgetStatus struct {
	Limit      int64            `json:"limit"`
	InUse      int64            `json:"inUse"`
	HighWater  int64            `json:"highWater"`
	ByCategory map[string]int64 `json:"byCategory"`
}

// Budget is immutable in capacity and belongs to one configuration generation.
// All admission and credit returns use atomics; no owner callbacks are invoked.
type Budget struct {
	limit      int64
	used       atomic.Int64
	high       atomic.Int64
	categories [categoryCount]atomic.Int64
}

// NewBudget accepts positive capacities, including small test budgets. Invalid
// capacities produce a closed budget, never an unlimited one.
func NewBudget(limit int64) *Budget { return &Budget{limit: max(0, limit)} }

func (b *Budget) charge(cl Class, cat Category, n int64) bool {
	if n <= 0 || cl > ClassObserve || cat >= categoryCount {
		return false
	}
	ceiling := b.limit
	if cl == ClassObserve {
		ceiling = ceiling/4*3 + ceiling%4*3/4
	}
	for {
		old := b.used.Load()
		if n > ceiling-old {
			return false
		}
		if b.used.CompareAndSwap(old, old+n) {
			b.categories[cat].Add(n)
			for h := b.high.Load(); old+n > h; h = b.high.Load() {
				if b.high.CompareAndSwap(h, old+n) {
					break
				}
			}
			return true
		}
	}
}
func (b *Budget) refund(cat Category, n int64) { b.categories[cat].Add(-n); b.used.Add(-n) }
func (b *Budget) Reserve(cl Class, cat Category, n int64) (*Lease, bool) {
	if !b.charge(cl, cat, n) {
		return nil, false
	}
	l := &Lease{budget: b, class: cl, category: cat}
	l.size.Store(n)
	return l, true
}

// Status is a best-effort concurrent sample; category counters may be sampled
// across a reservation or refund. A quiescent sample is exact.
func (b *Budget) Status() BudgetStatus {
	s := BudgetStatus{Limit: b.limit, InUse: b.used.Load(), HighWater: b.high.Load(), ByCategory: make(map[string]int64, categoryCount)}
	for c := Category(0); c < categoryCount; c++ {
		s.ByCategory[c.String()] = b.categories[c].Load()
	}
	return s
}

// Lease owns credit until Release. The negative size sentinel prevents an
// in-flight Grow from resurrecting a released lease. Leases must not be copied.
type Lease struct {
	budget   *Budget
	class    Class
	category Category
	size     atomic.Int64
}

func (l *Lease) Size() int64 { return max(0, l.size.Load()) }
func (l *Lease) Grow(n int64) bool {
	if n <= 0 || l.size.Load() < 0 || !l.budget.charge(l.class, l.category, n) {
		return false
	}
	for {
		old := l.size.Load()
		if old < 0 {
			l.budget.refund(l.category, n)
			return false
		}
		// charge's aggregate ceiling also guarantees old+n cannot overflow.
		if l.size.CompareAndSwap(old, old+n) {
			return true
		}
	}
}

// Shrink ignores invalid sizes and calls after Release; it never over-refunds.
func (l *Lease) Shrink(n int64) {
	if n <= 0 {
		return
	}
	for {
		old := l.size.Load()
		if n > old {
			return
		}
		if l.size.CompareAndSwap(old, old-n) {
			l.budget.refund(l.category, n)
			return
		}
	}
}
func (l *Lease) Release() {
	if old := l.size.Swap(-1); old >= 0 {
		l.budget.refund(l.category, old)
	}
}

// LimitOccupancy describes the budget's charged allocations, not uncharged heap.
func (b *Budget) LimitOccupancy() Occupancy {
	s := b.Status()
	return Occupancy{Limit: s.Limit, ChargedBytes: s.InUse, HighWater: s.HighWater}
}
