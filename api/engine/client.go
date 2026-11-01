// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

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

	"github.com/tonylturner/containd/pkg/common/enginetransport"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
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

func (c *HTTPClient) ApplyRules(ctx context.Context, snap rules.Snapshot) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/apply_rules", bytes.NewReader(body))
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
		return engineStatusError(resp, "engine apply_rules status")
	}
	return nil
}

func (c *HTTPClient) Configure(ctx context.Context, cfg config.DataPlaneConfig) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/config", bytes.NewReader(body))
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
		return fmt.Errorf("engine config status %d", resp.StatusCode)
	}
	return nil
}

// ConfigureServices applies every service and returns per-service runtime faults
// and warnings. Only request-level failures are returned as errors.
func (c *HTTPClient) ConfigureServices(ctx context.Context, services config.ServicesConfig) (ServicesApplyResult, error) {
	if c.BaseURL == "" {
		return ServicesApplyResult{}, fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(services)
	if err != nil {
		return ServicesApplyResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/services", bytes.NewReader(body))
	if err != nil {
		return ServicesApplyResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return ServicesApplyResult{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return ServicesApplyResult{}, fmt.Errorf("engine services response: %w", err)
	}
	if resp.StatusCode >= 300 {
		if detail := strings.TrimSpace(string(b)); detail != "" {
			return ServicesApplyResult{}, fmt.Errorf("engine services status %d: %s", resp.StatusCode, detail)
		}
		return ServicesApplyResult{}, fmt.Errorf("engine services status %d", resp.StatusCode)
	}
	var applied ServicesApplyResult
	if err := json.Unmarshal(b, &applied); err != nil {
		return ServicesApplyResult{}, fmt.Errorf("engine services response: %w", err)
	}
	if applied.Faults == nil {
		return ServicesApplyResult{}, fmt.Errorf("engine services response: missing faults")
	}
	seen := map[string]bool{}
	for _, fault := range applied.Faults {
		if (fault.Service != config.ServiceAV && fault.Service != config.ServiceWireGuard && fault.Service != config.ServiceDHCP) || fault.Kind != "runtime" || fault.Message == "" || seen[fault.Service] {
			return ServicesApplyResult{}, fmt.Errorf("engine services response: invalid runtime fault")
		}
		seen[fault.Service] = true
	}
	return applied, nil
}
