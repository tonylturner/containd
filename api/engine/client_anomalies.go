// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
)

// ListAnomalies fetches recent protocol anomalies, newest first, from the
// engine's anomaly detector.
func (c *HTTPClient) ListAnomalies(ctx context.Context, limit int) ([]anomaly.Anomaly, error) {
	u := c.BaseURL + "/internal/anomalies"
	if limit > 0 {
		u += "?limit=" + strconv.Itoa(limit)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, engineStatusError(resp, "engine anomalies status")
	}
	var out []anomaly.Anomaly
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/internal/anomalies", nil)
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return engineStatusError(resp, "engine anomalies clear status")
	}
	return nil
}
