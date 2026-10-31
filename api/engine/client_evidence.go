// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EvidenceError preserves domain HTTP status across the engine boundary.
type EvidenceError struct {
	Status int
	Detail string
}

func (e *EvidenceError) Error() string {
	return fmt.Sprintf("engine evidence status %d: %s", e.Status, e.Detail)
}

// Learn exchanges bounded normalized JSON with the sole evidence authority.
// actor is supplied by management authentication, never a forwarded user header.
func (c *HTTPClient) Learn(ctx context.Context, method, path, actor string, body json.RawMessage) (json.RawMessage, error) {
	if !strings.HasPrefix(path, "/learn/") {
		return nil, fmt.Errorf("invalid learning path")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+"/internal"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if actor != "" {
		req.Header.Set("X-Containd-Review-Actor", actor)
	}
	client := *c.Client
	if method == http.MethodPost && path == "/learn/generate" {
		client.Timeout = 10 * time.Minute
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	const maxResponse = 64 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponse {
		return nil, fmt.Errorf("oversized evidence response")
	}
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return nil, &EvidenceError{Status: resp.StatusCode, Detail: strings.TrimSpace(string(data))}
	}
	if resp.StatusCode == 204 {
		return nil, nil
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("invalid evidence response")
	}
	return data, nil
}
