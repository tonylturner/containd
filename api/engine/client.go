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
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
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

func (c *HTTPClient) ApplyRules(ctx context.Context, snap rules.Snapshot) (dpengine.ProtectionStatus, error) {
	if c.BaseURL == "" {
		return dpengine.ProtectionStatus{}, fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(snap)
	if err != nil {
		return dpengine.ProtectionStatus{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/apply_rules", bytes.NewReader(body))
	if err != nil {
		return dpengine.ProtectionStatus{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ApplyIDHeader, ApplyID(ctx))
	resp, err := c.Client.Do(req)
	if err != nil {
		return dpengine.ProtectionStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return dpengine.ProtectionStatus{}, engineStatusError(resp, "engine apply_rules status")
	}
	var observation dpengine.ProtectionStatus
	// A successful synchronous apply must not be undone for absent telemetry.
	if err := json.NewDecoder(resp.Body).Decode(&observation); err != nil {
		return UnknownProtection(ApplyID(ctx)), nil
	}
	return NormalizeProtection(observation, ApplyID(ctx)), nil
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
	req.Header.Set(ApplyIDHeader, ApplyID(ctx))
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return engineStatusError(resp, "engine config status")
	}
	return nil
}

// ConfigureServices applies the services configuration and returns the
// warnings the engine applied it with: conditions such as an AV backend that
// is still starting, which the engine resolves on its own without a further
// apply.
func (c *HTTPClient) ConfigureServices(ctx context.Context, services config.ServicesConfig) ([]string, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(services)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/services", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ApplyIDHeader, ApplyID(ctx))
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("engine services response: %w", err)
	}
	if resp.StatusCode >= 300 {
		if detail := strings.TrimSpace(string(b)); detail != "" {
			return nil, fmt.Errorf("engine services status %d: %s", resp.StatusCode, detail)
		}
		return nil, fmt.Errorf("engine services status %d", resp.StatusCode)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	var applied struct {
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(b, &applied); err != nil {
		return nil, fmt.Errorf("engine services response: %w", err)
	}
	return applied.Warnings, nil
}
