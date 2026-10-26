// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tonylturner/containd/pkg/common/trust"
)

// ConfigureTrust sends the additional CA bundle the engine's outbound TLS
// clients verify servers with.
func (c *HTTPClient) ConfigureTrust(ctx context.Context, b trust.Bundle) error {
	if c.BaseURL == "" {
		return errors.New("engine BaseURL is empty")
	}
	body, err := json.Marshal(b)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/trust", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return readStatusError(resp, "trust")
	}
	return nil
}
