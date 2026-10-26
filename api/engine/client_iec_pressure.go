// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tonylturner/containd/pkg/dp/engine"
)

// IEC104Diagnostics fetches live pressure from the engine, never cached zeros.
func (c *HTTPClient) IEC104Diagnostics(ctx context.Context) (engine.IEC104Pressure, error) {
	var out engine.IEC104Pressure
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/diagnostics/iec104", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, engineStatusError(resp, "engine IEC104 diagnostics status")
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	if err == nil && (out.Limits.Sessions <= 0 || out.Aborts == nil) {
		err = fmt.Errorf("engine IEC104 diagnostics missing pressure snapshot")
	}
	return out, err
}
