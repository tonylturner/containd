// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func showSystemSSH(store config.Store, api *API) Command {
	return func(ctx context.Context, out io.Writer, _ []string) error {
		if store == nil {
			// Resolve on the appliance, never from a remote CLI client's environment.
			return showRemoteSSHPolicy(ctx, api, out)
		}
		reader, ok := store.(interface {
			SSHRuntimePolicy(context.Context) (config.SSHRuntimePolicy, error)
		})
		if !ok {
			return errors.New("SSH runtime policy unavailable")
		}
		policy, err := reader.SSHRuntimePolicy(ctx)
		if err != nil {
			return err
		}
		if out != nil {
			kvTable(out, map[string]string{
				"allow_password":         yesNoStr(policy.AllowPassword),
				"password_source":        policy.PasswordSource,
				"authorized_keys_dir":    policy.AuthorizedKeysDir,
				"host_key_rotation_days": fmt.Sprint(policy.HostKeyRotationDays),
			})
		}
		return nil
	}
}

func showRemoteSSHPolicy(ctx context.Context, api *API, out io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.BaseURL+"/api/v1/cli/execute", strings.NewReader(`{"line":"show system ssh"}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if api.Token != "" {
		req.Header.Set("Authorization", "Bearer "+api.Token)
	}
	client := api.Client
	if client == nil {
		client = defaultHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	api.updateTokenFromResponse(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSH runtime policy: unexpected status %d", resp.StatusCode)
	}
	var result struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	if out != nil {
		_, err = io.WriteString(out, result.Output)
	}
	return err
}
