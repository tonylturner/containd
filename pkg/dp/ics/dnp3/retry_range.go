// SPDX-License-Identifier: Apache-2.0
package dnp3

import "github.com/tonylturner/containd/pkg/dp/dpi"

// retainRetryRange charges replacement capacity before copying. A retry at a
// new stream offset is carrying data, not permission to release a hole.
func (d *Decoder) retainRetryRange(c *stationContext, v dpi.StreamView, r LinkRange, reserved *int) error {
	a := c.transport
	if a == nil {
		return nil
	}
	if len(a.ranges) >= maxAssemblySegments {
		a.invalid = true
		return nil
	}
	needed := (len(a.ranges) + 1) * transportRangeBytes
	local, global := d.reserve(c.class, needed)
	if !local {
		a.invalid = true
		return nil
	}
	if !global {
		return d.budgetFailure(c, v)
	}
	*reserved += needed
	ranges := make([]transportRange, len(a.ranges)+1)
	copy(ranges, a.ranges)
	ranges[len(a.ranges)] = transportRange{LinkRange: r, retry: true}
	a.ranges = ranges
	return nil
}
