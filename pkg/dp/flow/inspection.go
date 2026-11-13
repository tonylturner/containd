// SPDX-License-Identifier: Apache-2.0
package flow

import "github.com/tonylturner/containd/pkg/dp/limits"

// InspectionMemory accounts for allocations with one immutable owner class.
// Its methods require the owning parser's lock. A replacement must reserve its
// full size before make/copy, then refund the old allocation after its last use.
type InspectionMemory struct {
	resources limits.Resources
	class     limits.Class
	category  limits.Category
	lease     *limits.Lease
}

func NewInspectionMemory(r limits.Resources, class limits.Class, category limits.Category) *InspectionMemory {
	return &InspectionMemory{resources: limits.NewResources(r.Budget, r.Ledger), class: class, category: category}
}

func (m *InspectionMemory) Reserve(n int) bool {
	if n == 0 {
		return true
	}
	if n < 0 {
		return false
	}
	if m.lease != nil {
		return m.lease.Grow(int64(n))
	}
	lease, ok := m.resources.Budget.Reserve(m.class, m.category, int64(n))
	if ok {
		m.lease = lease
	}
	return ok
}

func (m *InspectionMemory) Refund(n int) {
	if n > 0 {
		m.lease.Shrink(int64(n))
	}
}

func (m *InspectionMemory) Release() {
	if m.lease != nil {
		m.lease.Release()
	}
}
