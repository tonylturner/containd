// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

// StateLimits fetches live state limits from the engine, never cached zeros.
func (c *HTTPClient) StateLimits(ctx context.Context) (limits.Snapshot, error) {
	var out limits.Snapshot
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/diagnostics/state-limits", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, engineStatusError(resp, "engine state limits diagnostics status")
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	if err == nil && (out.Budget.Limit <= 0 || out.Budget.ByCategory == nil || len(out.Tables) == 0) {
		err = fmt.Errorf("engine state limits diagnostics missing pressure snapshot")
	}
	return out, err
}
