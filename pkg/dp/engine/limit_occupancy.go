// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/tonylturner/containd/pkg/dp/itdpi"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func (t *iecTable) LimitOccupancy() limits.Occupancy {
	t.mu.Lock()
	defer t.mu.Unlock()
	return limits.Occupancy{Limit: iecMaxSessions, Entries: int64(len(t.sessions))}
}
func (t *iecTable) reconnectLimitOccupancy() limits.Occupancy {
	t.mu.Lock()
	defer t.mu.Unlock()
	return limits.Occupancy{Limit: iecMaxReconnectHistory, Entries: int64(len(t.reconnect))}
}

func (e *Engine) httpCorrelationOccupancy() limits.Occupancy {
	var out limits.Occupancy
	// The observation manager only registers ICS decoders. HTTP belongs solely
	// to the legacy manager; decoder-local locks serialize concurrent parsing.
	for _, decoder := range e.dpiMgr.Decoders() {
		if d, ok := decoder.(*itdpi.HTTPDecoder); ok {
			o := d.LimitOccupancy()
			out.Entries += o.Entries
			out.Limit += o.Limit
		}
	}
	return out
}
