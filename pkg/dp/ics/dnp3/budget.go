// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

// SetResources installs generation-scoped accounting before the first packet.
func (d *Decoder) SetResources(r limits.Resources) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.stations) != 0 {
		panic("dnp3: cannot replace resources of a live decoder")
	}
	d.resources = limits.NewResources(r.Budget, r.Ledger)
}

func (d *Decoder) retainedBytes() int {
	n := int64(0)
	for _, lease := range d.leases {
		if lease != nil {
			n += lease.Size()
		}
	}
	return int(n)
}

func (d *Decoder) localLimit() int {
	return int(min(int64(maxRetainedBytes), d.resources.Budget.Status().Limit/4))
}

// reserve checks the aggregate local peak under mu before growing the owning
// class's lease. Local exhaustion is a protocol finding, not a global refusal.
func (d *Decoder) reserve(class limits.Class, n int) (local, global bool) {
	if n > d.localLimit()-d.retainedBytes() {
		return false, true
	}
	if n == 0 {
		return true, true
	}
	if d.leases[class] != nil {
		return true, d.leases[class].Grow(int64(n))
	}
	lease, ok := d.resources.Budget.Reserve(class, limits.CategoryDecoder, int64(n))
	if ok {
		d.leases[class] = lease
	}
	return true, ok
}

func (d *Decoder) refund(class limits.Class, n int) {
	if n == 0 {
		return
	}
	lease := d.leases[class]
	lease.Shrink(int64(n))
	if lease.Size() == 0 {
		lease.Release()
		d.leases[class] = nil
	}
}

func (d *Decoder) budgetFailure(c *stationContext, v dpi.StreamView) *dpi.StreamError {
	if c.failure == nil {
		c.failure = dpi.StateLimitError(d.resources, c.class == limits.ClassEnforce, "dnp3", v.Base)
	}
	c.transport, c.retry = nil, nil
	return c.failure
}
