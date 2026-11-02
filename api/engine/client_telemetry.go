// SPDX-License-Identifier: Apache-2.0

package engineapi

import (
	"context"

	"github.com/tonylturner/containd/pkg/common/telemetry"
)

var _ telemetry.CounterReader = (*HTTPClient)(nil)

// TelemetryCounters reads cumulative engine counters, including source failures.
func (c *HTTPClient) TelemetryCounters(ctx context.Context) (telemetry.CounterSnapshot, error) {
	var out telemetry.CounterSnapshot
	err := c.getJSON(ctx, "/internal/telemetry/counters", "engine telemetry counters status", &out)
	return out, err
}
