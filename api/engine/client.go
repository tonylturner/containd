package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"net/http"
	"time"

	"github.com/containd/containd/pkg/cp/config"
	dpevents "github.com/containd/containd/pkg/dp/events"
	"github.com/containd/containd/pkg/dp/rules"
)

// HTTPClient applies runtime config and snapshots to a remote ngfw-engine via internal HTTP.
type HTTPClient struct {
	BaseURL string
	Client  *http.Client
}

func NewHTTPClient(baseURL string) *HTTPClient {
	return &HTTPClient{
		BaseURL: baseURL,
		Client:  &http.Client{Timeout: 5 * time.Second},
	}
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
		return fmt.Errorf("engine apply_rules status %d", resp.StatusCode)
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
	return out, nil
}
