// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"slices"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
)

// This private coverage key retains dimension-scoped activity independently of
// the metric-wide chart latches. Coverage survives bucket and series retention.
const demoSecurityCoverage = "demo.engine_security"

var demoSecurityClasses = [...]string{string(wire.ClassIDSAlert), string(wire.ClassAVDetection), string(wire.ClassAVBlock)}

func demoSecuritySample(sample wire.CounterSample) bool {
	return sample.Metric == wire.EventsClass && sample.Dims["source"] == "engine" &&
		slices.Contains(demoSecurityClasses[:], sample.Dims["class"])
}

// restoreDemoSecurity retains qualifying history from stores written before the
// dimension-scoped latch existed. Stored values are canonical unsigned varints,
// so every non-null value other than x'00' is positive (including uint64 maxima).
func (s *Store) restoreDemoSecurity(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO coverage(metric,covered,active)
 SELECT ?,1,1 WHERE EXISTS (
 SELECT 1 FROM series s JOIN buckets b ON b.series=s.id
 WHERE s.origin='real' AND s.metric='events.class'
 AND json_extract(s.dims,'$.source')='engine'
 AND json_extract(s.dims,'$.class') IN (?,?,?)
 AND b.v IS NOT NULL AND b.v != x'00')
 ON CONFLICT(metric) DO UPDATE SET covered=1,active=1`,
		demoSecurityCoverage, demoSecurityClasses[0], demoSecurityClasses[1], demoSecurityClasses[2])
	return err
}

// DemoState stops auto only for routed bytes or engine security events.
// Chart RealActive semantics remain metric-wide and independent of this latch.
// Readiness is process-local: retained coverage cannot stand in for this
// sampler completing its first observed interval after a management restart.
func (s *Store) DemoState(ctx context.Context) (observed, realActive bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var active int
	err = s.db.QueryRowContext(ctx, `SELECT coalesce(max(active),0) FROM coverage WHERE metric IN ('conduit.bytes',?)`, demoSecurityCoverage).Scan(&active)
	return s.observedInterval && s.state.State == "running", active != 0, err
}
