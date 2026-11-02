// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// requestBytes preserves file input exactly, including keys the API must reject.
func (a *API) requestBytes(ctx context.Context, method, path string, body []byte, revision config.Revision) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if revision != "" {
		req.Header.Set("X-Containd-If-Revision", string(revision))
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	client := a.Client
	if client == nil {
		client = defaultHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	a.updateTokenFromResponse(resp)
	if resp.StatusCode >= 300 {
		return nil, nil, mutationError(resp)
	}
	if revision != "" && !config.Revision(resp.Header.Get("X-Containd-Revision")).Valid() {
		return nil, nil, fmt.Errorf("successful configuration write returned no valid revision")
	}
	raw, err := io.ReadAll(resp.Body)
	return raw, resp.Header, err
}

func opsRead(api *API, path string) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 0 {
			return fmt.Errorf("this inspection command takes no arguments")
		}
		raw, _, err := api.requestBytes(ctx, http.MethodGet, path, nil, "")
		if err != nil {
			return err
		}
		return opsPrint(out, raw)
	}
}

func opsPrint(out io.Writer, raw []byte) error {
	if out == nil {
		return nil
	}
	var value json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("invalid API response: %w", err)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("API returned no data")
	}
	return printJSON(out, value)
}

// opsImmediate intentionally never uses mutateJSON: backup operations live
// under /config but do not edit the candidate or need a candidate revision.
func opsImmediate(ctx context.Context, api *API, out io.Writer, method, path string, payload any) error {
	var raw []byte
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	if out != nil {
		fmt.Fprintln(out, "Immediate operation requested; not staged and does not require commit.")
	}
	response, _, err := api.requestBytes(ctx, method, path, raw, "")
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(response)) == 0 {
		return nil
	}
	return opsPrint(out, response)
}

func opsDownload(api *API, path func(string) string, usage string) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("usage: %s <id> <new-file>", usage)
		}
		raw, _, err := api.requestBytes(ctx, http.MethodGet, path(args[0]), nil, "")
		if err != nil {
			return err
		}
		// A new, private file avoids truncating an existing secret or following a symlink.
		file, err := os.OpenFile(args[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(raw)
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		if out != nil {
			fmt.Fprintln(out, "Downloaded to private file:", args[1])
		}
		return nil
	}
}
