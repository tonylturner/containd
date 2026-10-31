// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/tonylturner/containd/pkg/dp/engine"
)

// PreviewRule delegates candidate matching to the engine's live context.
func (c *HTTPClient) PreviewRule(ctx context.Context, request engine.PreviewRuleRequest) (engine.PreviewRuleResponse, error) {
	var out engine.PreviewRuleResponse
	body, err := json.Marshal(request)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/rules/preview", bytes.NewReader(body))
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
		return out, engineStatusError(resp, "engine rule preview status")
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}
