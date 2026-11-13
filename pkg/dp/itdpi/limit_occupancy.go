// SPDX-License-Identifier: Apache-2.0

package itdpi

import "github.com/tonylturner/containd/pkg/dp/limits"

// LimitOccupancy counts retained correlation requests across connections.
// There is no global correlation cap; each connection has a fixed FIFO cap.
func (d *HTTPDecoder) LimitOccupancy() limits.Occupancy {
	d.mu.Lock()
	defer d.mu.Unlock()
	o := limits.Occupancy{}
	for _, c := range d.connections {
		o.Entries += c.LimitOccupancy().Entries
	}
	return o
}

// LimitOccupancy requires the owning HTTPDecoder's mutex. It describes one
// connection FIFO, not a decoder-wide admission bound.
func (c *httpConnection) LimitOccupancy() limits.Occupancy {
	return limits.Occupancy{Limit: maxHTTPRequestMethods, Entries: int64(len(c.methods))}
}
