// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/enginetransport"
)

// HTTPClient applies runtime config and snapshots to the engine via internal HTTP.
type HTTPClient struct {
	BaseURL string
	Client  *http.Client
}

// NewHTTPClient preserves credential-free loopback callers. Invalid targets
// produce a client that refuses every request; application startup should use
// Resolve and NewHTTPClientForTarget to report configuration errors eagerly.
func NewHTTPClient(baseURL string) *HTTPClient {
	target, err := enginetransport.Resolve(baseURL)
	if err != nil {
		return &HTTPClient{BaseURL: baseURL, Client: &http.Client{Timeout: 5 * time.Second, Transport: refusedTransport{err}}}
	}
	return NewHTTPClientForTarget(target)
}

func NewHTTPClientForTarget(target *enginetransport.Target) *HTTPClient {
	return &HTTPClient{BaseURL: target.URL(), Client: target.Client(5 * time.Second)}
}

type refusedTransport struct{ err error }

func (t refusedTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

func engineStatusError(resp *http.Response, prefix string) error {
	body, _ := io.ReadAll(resp.Body)
	detail := strings.TrimSpace(string(body))
	if detail == "" {
		return fmt.Errorf("%s %d", prefix, resp.StatusCode)
	}
	return fmt.Errorf("%s %d: %s", prefix, resp.StatusCode, detail)
}

// getJSON decodes the 200 response of a GET to path into out. Any other
// status returns an error that starts with statusPrefix.
func (c *HTTPClient) getJSON(ctx context.Context, path, statusPrefix string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return engineStatusError(resp, statusPrefix)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// deleteOK sends a DELETE to path and requires a 200 response. Any other
// status returns an error that starts with statusPrefix.
func (c *HTTPClient) deleteOK(ctx context.Context, path, statusPrefix string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return engineStatusError(resp, statusPrefix)
	}
	return nil
}
