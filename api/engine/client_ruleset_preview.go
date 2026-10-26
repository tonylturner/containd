// SPDX-License-Identifier: Apache-2.0

package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// rulesetPreviewRequest is the body of POST /internal/ruleset/preview: the
// candidate and its snapshot compiled by this (management) process.
type rulesetPreviewRequest struct {
	Config   *config.Config `json:"config"`
	Snapshot rules.Snapshot `json:"snapshot"`
}

// PreviewRuleset compiles the candidate's snapshot here, as an apply does,
// so its management INPUT admits the listeners this process resolves and
// has bound; the engine compiles the ruleset under its runtime authority.
func (c *HTTPClient) PreviewRuleset(ctx context.Context, cfg *config.Config) (engine.RulesetPreview, error) {
	var out engine.RulesetPreview
	snap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		return out, err
	}
	body, err := json.Marshal(rulesetPreviewRequest{Config: cfg, Snapshot: snap})
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
