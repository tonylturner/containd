// SPDX-License-Identifier: Apache-2.0
package observe

import (
	"strings"
	"unsafe"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/identify"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func (c *connection) clearStamps() {
	c.stamps = nil
	c.memory.Refund(c.stampCharge)
	c.stampCharge = 0
}

func (c *connection) appendStamp(s stamp) bool {
	size := (len(c.stamps) + 1) * int(unsafe.Sizeof(stamp{}))
	if !c.memory.Reserve(size) {
		return false
	}
	next := make([]stamp, len(c.stamps)+1)
	copy(next, c.stamps)
	next[len(c.stamps)] = s
	old := c.stampCharge
	c.stamps, c.stampCharge = next, size
	c.memory.Refund(old)
	return true
}

func (o *Observer) markInspectionLoss(c *connection, record bool) {
	if !c.inspectionLost {
		c.inspectionLost = true
		if record {
			o.opts.Manager.InspectionResources().Ledger.Record(limits.TableInspection, limits.ReasonRefused, limits.ModeMonitor)
		}
	}
	c.coverage = identify.Truncated
	o.endBinding(c)
}

func (o *Observer) inspectionLoss(key identify.Key, c *connection) Output {
	if !c.inspectionLost || c.lossReported {
		return Output{}
	}
	c.lossReported = true
	d := c.lastDir
	return Output{Batches: []Batch{{Key: key, Dir: d, State: c.states[d], At: c.at[d],
		Err: &dpi.StreamError{Kind: dpi.StreamStateLimit}}}}
}

func (o *Observer) releaseConnection(key identify.Key, c *connection) {
	delete(o.entries, key)
	o.table.Release(key)
	c.clearStamps()
	c.session = ""
	c.memory.Release()
}

// Prepare both old and new key backing before adoption mutates either owner.
func (c *connection) reserveKey(to identify.Key) (identify.Key, bool) {
	if !c.memory.Reserve(len(to)) {
		return "", false
	}
	return identify.Key(strings.Clone(string(to))), true
}

func (o *Observer) moveConnection(from, to identify.Key, c *connection) {
	delete(o.entries, from)
	o.entries[to] = c
	c.memory.Refund(c.keyBytes)
	c.keyBytes = len(to)
}
