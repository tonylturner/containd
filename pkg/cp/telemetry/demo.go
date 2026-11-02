// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
)

// DemoState uses the same persistent activity latch as SeriesResponse.RealActive.
// Readiness is process-local: retained coverage cannot stand in for this
// sampler completing its first observed interval after a management restart.
func (s *Store) DemoState(ctx context.Context) (observed, realActive bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var active int
	err = s.db.QueryRowContext(ctx, `SELECT coalesce(max(active),0) FROM coverage WHERE metric IN ('iface.rx_bytes','iface.tx_bytes','conduit.bytes')`).Scan(&active)
	return s.observedInterval && s.state.State == "running", active != 0, err
}
