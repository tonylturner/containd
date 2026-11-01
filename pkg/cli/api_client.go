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

	"github.com/tonylturner/containd/pkg/cp/config"
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
	_, err := a.readJSON(ctx, path, into)
	return err
}

func (a *API) readJSON(ctx context.Context, path string, into any) (config.Revision, error) {
	if a.Client == nil {
		a.Client = defaultHTTPClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.BaseURL+path, nil)
	if err != nil {
		return "", err
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	a.updateTokenFromResponse(resp)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return config.Revision(resp.Header.Get("X-Containd-Revision")), json.NewDecoder(resp.Body).Decode(into)
}

// getConfigJSON requires an authoritative value before a read-modify-write.
// In particular, JSON null must not turn a failed load into a zero-value edit.
func (a *API) getConfigJSON(ctx context.Context, path string, into any) (config.Revision, error) {
	var raw json.RawMessage
	revision, err := a.readJSON(ctx, path, &raw)
	if err != nil {
		return "", fmt.Errorf("cannot read current config from %s: %w", path, err)
	}
	if !revision.Valid() {
		return "", fmt.Errorf("cannot read current config from %s: missing or invalid revision", path)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("cannot read current config from %s: no data", path)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return "", fmt.Errorf("cannot read current config from %s: %w", path, err)
	}
	return revision, nil
}

func (a *API) postJSON(ctx context.Context, path string, payload any, out io.Writer) error {
	return a.mutateJSON(ctx, http.MethodPost, path, payload, nil, out)
}

func (a *API) mutateJSON(ctx context.Context, method, path string, payload, into any, out io.Writer) error {
	var revision config.Revision
	if isConfigWrite(path) {
		var raw json.RawMessage
		var err error
		revision, err = a.getConfigJSON(ctx, "/api/v1/config/candidate", &raw)
		if err != nil {
			return err
		}
	}
	_, err := a.mutateRevisionJSON(ctx, method, path, payload, into, revision, out)
	return err
}

func (a *API) saveJSON(ctx context.Context, path string, payload any, revision config.Revision, out io.Writer) error {
	_, err := a.mutateRevisionJSON(ctx, http.MethodPost, path, payload, nil, revision, out)
	return err
}

func (a *API) mutateRevisionJSON(ctx context.Context, method, path string, payload, into any, revision config.Revision, out io.Writer) (config.Revision, error) {
	if a.Client == nil {
		a.Client = defaultHTTPClient
	}
	buf := &bytes.Buffer{}
	if payload != nil || method == http.MethodPost {
		if err := json.NewEncoder(buf).Encode(payload); err != nil {
			return "", err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, buf)
	if err != nil {
		return "", err
	}
	if method == http.MethodPost || method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/json")
	}
	if revision != "" {
		req.Header.Set("X-Containd-If-Revision", string(revision))
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	a.updateTokenFromResponse(resp)
	if resp.StatusCode >= 300 {
		return "", mutationError(resp)
	}
	next := config.Revision(resp.Header.Get("X-Containd-Revision"))
	if revision != "" && !next.Valid() {
		return "", fmt.Errorf("successful configuration write returned no valid revision")
	}
	if out != nil {
		writeMutationResult(out, resp.Header.Get("X-Containd-Config"))
		for _, warning := range resp.Header.Values("X-Containd-Warnings") {
			fmt.Fprintln(out, "Warning:", warning)
		}
	}
	if method == http.MethodPost && resp.Header.Get(SSHResetResponseHeader) == "true" {
		return next, a.acknowledgeSSHReset(ctx)
	}
	if into != nil {
		return next, json.NewDecoder(resp.Body).Decode(into)
	}
	return next, nil
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
	return a.mutateJSON(ctx, http.MethodPatch, path, payload, nil, out)
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
