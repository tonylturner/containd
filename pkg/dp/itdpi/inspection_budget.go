// SPDX-License-Identifier: Apache-2.0
package itdpi

import (
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func decoderMemory(r limits.Resources, enforcing bool, size int) *flow.InspectionMemory {
	class := limits.ClassObserve
	if enforcing {
		class = limits.ClassEnforce
	}
	m := flow.NewInspectionMemory(r, class, limits.CategoryDecoder)
	if !m.Reserve(size) {
		return nil
	}
	return m
}

// replaceBytes reserves the full replacement while the old backing is live.
func replaceBytes(m *flow.InspectionMemory, target *[]byte, extra []byte) bool {
	size := len(*target) + len(extra)
	if !m.Reserve(size) {
		return false
	}
	oldSize := cap(*target)
	buf := make([]byte, size)
	copy(buf, *target)
	copy(buf[len(*target):], extra)
	*target = buf
	m.Refund(oldSize)
	return true
}

func (d *HTTPDecoder) SetResources(r limits.Resources) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.streams) != 0 {
		panic("http: cannot replace live inspection resources")
	}
	d.resources = limits.NewResources(r.Budget, r.Ledger)
}

func (d *TLSDecoder) SetResources(r limits.Resources) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.streams) != 0 {
		panic("tls: cannot replace live inspection resources")
	}
	d.resources = limits.NewResources(r.Budget, r.Ledger)
}
