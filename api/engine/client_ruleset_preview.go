// SPDX-License-Identifier: Apache-2.0

package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/engine"
)

// PreviewRuleset compiles the candidate using the engine's runtime authority.
func (c *HTTPClient) PreviewRuleset(ctx context.Context, cfg *config.Config) (engine.RulesetPreview, error) {
	var out engine.RulesetPreview
	body, err := json.Marshal(cfg)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/ruleset/preview", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, engineStatusError(resp, "engine ruleset preview status")
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}
