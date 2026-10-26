// SPDX-License-Identifier: Apache-2.0

package engineapi

import (
	"context"
	"encoding/json"
	"net/http"

	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

// RuleCounters reads the per-rule counters of the applied ruleset.
func (c *HTTPClient) RuleCounters(ctx context.Context) (dpengine.RuleCounters, error) {
	var out dpengine.RuleCounters
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/firewall/counters", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, engineStatusError(resp, "engine rule counters status")
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}
