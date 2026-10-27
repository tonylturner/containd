// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/services"
)

// avUploadTimeout covers streaming a definition and the engine validating it.
const avUploadTimeout = 3 * time.Minute

// StatusError is a non-2xx engine reply. Code lets management pass engine
// request errors through while treating transport failures as unavailable.
type StatusError struct {
	Op     string
	Code   int
	Detail string
}

func (e *StatusError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("engine %s status %d", e.Op, e.Code)
	}
	return fmt.Sprintf("engine %s status %d: %s", e.Op, e.Code, e.Detail)
}

func readStatusError(resp *http.Response, op string) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &StatusError{Op: op, Code: resp.StatusCode, Detail: strings.TrimSpace(string(body))}
}

func (c *HTTPClient) avRequest(ctx context.Context, client *http.Client, method, path string, body io.Reader, op string, out any) error {
	if c.BaseURL == "" {
		return errors.New("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return readStatusError(resp, op)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// AVStatus returns the engine scanner's live status.
func (c *HTTPClient) AVStatus(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := c.avRequest(ctx, c.Client, http.MethodGet, "/internal/av/status", nil, "av status", &out)
	return out, err
}

// TriggerAVUpdate queues an immediate FreshClam update on the engine.
func (c *HTTPClient) TriggerAVUpdate(ctx context.Context) error {
	return c.avRequest(ctx, c.Client, http.MethodPost, "/internal/av/update", nil, "av update", nil)
}

// ListAVDefs lists the engine's custom signature databases.
func (c *HTTPClient) ListAVDefs(ctx context.Context) (services.AVDefinitionList, error) {
	var out services.AVDefinitionList
	err := c.avRequest(ctx, c.Client, http.MethodGet, "/internal/av/defs", nil, "av defs", &out)
	return out, err
}

// UploadAVDef streams a custom signature database to the engine.
func (c *HTTPClient) UploadAVDef(ctx context.Context, name string, r io.Reader) (services.AVDefinition, error) {
	var out services.AVDefinition
	client := *c.Client
	client.Timeout = avUploadTimeout
	err := c.avRequest(ctx, &client, http.MethodPost, "/internal/av/defs?name="+url.QueryEscape(name), r, "av defs upload", &out)
	return out, err
}

// DeleteAVDef removes a custom signature database on the engine.
func (c *HTTPClient) DeleteAVDef(ctx context.Context, name string) error {
	return c.avRequest(ctx, c.Client, http.MethodDelete, "/internal/av/defs?name="+url.QueryEscape(name), nil, "av defs delete", nil)
}
