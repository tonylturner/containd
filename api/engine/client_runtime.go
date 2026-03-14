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
	"net/url"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

// SimulationStatus holds the state of the synthetic traffic generator.
type SimulationStatus struct {
	Running bool `json:"running"`
}

// ListEvents fetches recent normalized events from the engine.
func (c *HTTPClient) ListEvents(ctx context.Context, limit int) ([]dpevents.Event, error) {
	u := c.BaseURL + "/internal/events"
	if limit > 0 {
		u += "?limit=" + url.QueryEscape(fmt.Sprintf("%d", limit))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine events status %d", resp.StatusCode)
	}
	var out []dpevents.Event
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListProtoStats fetches protocol counters derived from live DPI events.
func (c *HTTPClient) ListProtoStats(ctx context.Context) ([]stats.ProtoStats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/stats/protocols", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, engineStatusError(resp, "engine protocol stats status")
	}
	var out []stats.ProtoStats
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return []stats.ProtoStats{}, nil
	}
	return out, nil
}

// ListTopTalkers fetches top flow summaries derived from live DPI events.
func (c *HTTPClient) ListTopTalkers(ctx context.Context, n int) ([]stats.FlowStats, error) {
	u := c.BaseURL + "/internal/stats/top-talkers"
	if n > 0 {
		u += "?n=" + url.QueryEscape(fmt.Sprintf("%d", n))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, engineStatusError(resp, "engine top-talkers status")
	}
	var out []stats.FlowStats
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return []stats.FlowStats{}, nil
	}
	return out, nil
}

// ListInventory fetches discovered ICS assets from the engine.
func (c *HTTPClient) ListInventory(ctx context.Context) ([]inventory.DiscoveredAsset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/inventory", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, engineStatusError(resp, "engine inventory status")
	}
	var out []inventory.DiscoveredAsset
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return []inventory.DiscoveredAsset{}, nil
	}
	return out, nil
}

// GetInventoryAsset fetches a discovered ICS asset by IP.
func (c *HTTPClient) GetInventoryAsset(ctx context.Context, ip string) (*inventory.DiscoveredAsset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/inventory/"+url.PathEscape(strings.TrimSpace(ip)), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, engineStatusError(resp, "engine inventory asset status")
	}
	var out inventory.DiscoveredAsset
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ClearInventory clears the engine-side discovered asset inventory.
func (c *HTTPClient) ClearInventory(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/internal/inventory", nil)
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return engineStatusError(resp, "engine inventory clear status")
	}
	return nil
}

func (c *HTTPClient) ListConntrack(ctx context.Context, limit int) ([]conntrack.Entry, error) {
	u := c.BaseURL + "/internal/conntrack"
	if limit > 0 {
		u += "?limit=" + url.QueryEscape(fmt.Sprintf("%d", limit))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine conntrack status %d", resp.StatusCode)
	}
	var out struct {
		Entries []conntrack.Entry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Entries == nil {
		return []conntrack.Entry{}, nil
	}
	return out.Entries, nil
}

func (c *HTTPClient) ListDHCPLeases(ctx context.Context) ([]dhcpd.Lease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/dhcp/leases", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("engine dhcp leases status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Leases []dhcpd.Lease `json:"leases"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Leases, nil
}

func (c *HTTPClient) DeleteConntrack(ctx context.Context, req conntrack.DeleteRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/conntrack", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("engine conntrack delete status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// ListFlows fetches recent flow summaries derived from events.
func (c *HTTPClient) ListFlows(ctx context.Context, limit int) ([]dpevents.FlowSummary, error) {
	u := c.BaseURL + "/internal/flows"
	if limit > 0 {
		u += "?limit=" + url.QueryEscape(fmt.Sprintf("%d", limit))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine flows status %d", resp.StatusCode)
	}
	var out []dpevents.FlowSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return []dpevents.FlowSummary{}, nil
	}
	return out, nil
}

// SimulationStatus returns whether the synthetic traffic generator is running.
func (c *HTTPClient) SimulationStatus(ctx context.Context) (SimulationStatus, error) {
	if c.BaseURL == "" {
		return SimulationStatus{}, fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/simulation", nil)
	if err != nil {
		return SimulationStatus{}, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return SimulationStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SimulationStatus{}, engineStatusError(resp, "engine simulation status")
	}
	var st SimulationStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return SimulationStatus{}, err
	}
	return st, nil
}

// SimulationControl sends a start or stop action to the synthetic traffic generator.
func (c *HTTPClient) SimulationControl(ctx context.Context, action string) (SimulationStatus, error) {
	if c.BaseURL == "" {
		return SimulationStatus{}, fmt.Errorf("engine BaseURL is empty")
	}
	body, _ := json.Marshal(map[string]string{"action": action})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/simulation", bytes.NewReader(body))
	if err != nil {
		return SimulationStatus{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return SimulationStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SimulationStatus{}, engineStatusError(resp, "engine simulation control")
	}
	var st SimulationStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return SimulationStatus{}, err
	}
	return st, nil
}
