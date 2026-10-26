// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/signatures"
)

// ErrSignatureExists reports that the engine already holds a signature with
// the ID being added.
var ErrSignatureExists = errors.New("signature already exists")

// ListSignatures fetches the signatures the engine has loaded.
func (c *HTTPClient) ListSignatures(ctx context.Context) ([]signatures.Signature, error) {
	var out []signatures.Signature
	if err := c.getJSON(ctx, "/internal/signatures", "engine signatures status", &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("invalid engine signature list")
	}
	return out, nil
}

// AddSignature loads a live signature into the engine. It lasts until the
// engine restarts. An ID the engine already holds returns ErrSignatureExists.
func (c *HTTPClient) AddSignature(ctx context.Context, sig signatures.Signature) error {
	body, err := json.Marshal(sig)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/signatures", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		return ErrSignatureExists
	default:
		return engineStatusError(resp, "engine signature add status")
	}
}

// RemoveSignature removes a loaded signature by ID. It reports false when the
// engine holds no signature with that ID.
func (c *HTTPClient) RemoveSignature(ctx context.Context, id string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/internal/signatures?id="+url.QueryEscape(id), nil)
	if err != nil {
		return false, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, engineStatusError(resp, "engine signature remove status")
	}
}

// ListSignatureMatches fetches recent signature matches, newest first.
func (c *HTTPClient) ListSignatureMatches(ctx context.Context, limit int) ([]signatures.Match, error) {
	path := "/internal/signatures/matches"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var out []signatures.Match
	if err := c.getJSON(ctx, path, "engine signature matches status", &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("invalid engine signature match list")
	}
	return out, nil
}
