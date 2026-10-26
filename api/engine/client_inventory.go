// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tonylturner/containd/pkg/dp/inventory"
)

// IEC104Inventory fetches the passive station/CA/point inventory and overflow totals.
func (c *HTTPClient) IEC104Inventory(ctx context.Context) (inventory.IEC104Snapshot, error) {
	var out inventory.IEC104Snapshot
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/inventory?section=iec104", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, engineStatusError(resp, "engine IEC104 inventory status")
	}
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	if out.Pairs == nil || out.Limits.Pairs <= 0 || out.Limits.CAsPerPair <= 0 || out.Limits.PointsPerCA <= 0 {
		return inventory.IEC104Snapshot{}, fmt.Errorf("invalid engine IEC104 inventory snapshot")
	}
	return out, nil
}
