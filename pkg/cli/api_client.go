// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

var defaultHTTPClient = &http.Client{Timeout: 15 * time.Second}

// API wraps HTTP interactions with the management plane.
type API struct {
	BaseURL string
	Client  HTTPClient
	Token   string
}

func (a *API) updateTokenFromResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	if tok := strings.TrimSpace(resp.Header.Get("X-Auth-Token")); tok != "" {
		a.Token = tok
	}
}

func (a *API) getJSON(ctx context.Context, path string, into any) error {
	if a.Client == nil {
		a.Client = defaultHTTPClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.BaseURL+path, nil)
	if err != nil {
		return err
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	a.updateTokenFromResponse(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

// getConfigJSON requires an authoritative value before a read-modify-write.
// In particular, JSON null must not turn a failed load into a zero-value edit.
func (a *API) getConfigJSON(ctx context.Context, path string, into any) error {
	var raw json.RawMessage
	if err := a.getJSON(ctx, path, &raw); err != nil {
		return fmt.Errorf("cannot read current config from %s: %w", path, err)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("cannot read current config from %s: no data", path)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("cannot read current config from %s: %w", path, err)
	}
	return nil
}

func (a *API) postJSON(ctx context.Context, path string, payload any, out io.Writer) error {
	return a.mutateJSON(ctx, http.MethodPost, path, payload, nil, out)
}

func (a *API) mutateJSON(ctx context.Context, method, path string, payload, into any, out io.Writer) error {
	if a.Client == nil {
		a.Client = defaultHTTPClient
	}
	buf := &bytes.Buffer{}
	if payload != nil || method == http.MethodPost {
		if err := json.NewEncoder(buf).Encode(payload); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, buf)
	if err != nil {
		return err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	a.updateTokenFromResponse(resp)
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	if out != nil {
		writeMutationResult(out, resp.Header.Get("X-Containd-Config"))
		for _, warning := range resp.Header.Values("X-Containd-Warnings") {
			fmt.Fprintln(out, "Warning:", warning)
		}
	}
	if method == http.MethodPost && resp.Header.Get(SSHResetResponseHeader) == "true" {
		return a.acknowledgeSSHReset(ctx)
	}
	if into != nil {
		return json.NewDecoder(resp.Body).Decode(into)
	}
	return nil
}

func (a *API) postMultipartFile(ctx context.Context, path string, filename string, file io.Reader, out any) error {
	if a.Client == nil {
		a.Client = defaultHTTPClient
	}
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	go func() {
		part, err := writer.CreateFormFile("file", filename)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := writer.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+path, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	a.updateTokenFromResponse(resp)
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (a *API) patchJSON(ctx context.Context, path string, payload any, out io.Writer) error {
	if a.Client == nil {
		a.Client = defaultHTTPClient
	}
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, a.BaseURL+path, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	a.updateTokenFromResponse(resp)
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	if out != nil {
		writeMutationResult(out, resp.Header.Get("X-Containd-Config"))
	}
	return nil
}

func (a *API) delete(ctx context.Context, path string, out io.Writer) error {
	return a.mutateJSON(ctx, http.MethodDelete, path, nil, nil, out)
}

func (a *API) acknowledgeSSHReset(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+SSHResetAcknowledgePath, nil)
	if err != nil {
		return err
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected SSH reset acknowledgement status %d", resp.StatusCode)
	}
	return nil
}

// Only persistent config edits are staged; operational and commit output stays unchanged.
const stagedMessage = `staged; run "commit" to apply`

func writeMutationResult(out io.Writer, state string) {
	if out == nil {
		return
	}
	if state == "staged" {
		fmt.Fprintln(out, stagedMessage)
	} else {
		fmt.Fprintln(out, "ok")
	}
}
