// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"fmt"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
)

// ListAnomalies fetches recent protocol anomalies, newest first, from the
// engine's anomaly detector.
func (c *HTTPClient) ListAnomalies(ctx context.Context, limit int) ([]anomaly.Anomaly, error) {
	path := "/internal/anomalies"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var out []anomaly.Anomaly
	if err := c.getJSON(ctx, path, "engine anomalies status", &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("invalid engine anomaly list")
	}
	return out, nil
}

// ClearAnomalies resets the engine's anomaly detector, including its
// recorded anomalies.
func (c *HTTPClient) ClearAnomalies(ctx context.Context) error {
	return c.deleteOK(ctx, "/internal/anomalies", "engine anomalies clear status")
}
