// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func showSystemSSH(store config.Store, api *API) Command {
	return func(ctx context.Context, out io.Writer, _ []string) error {
		if store == nil {
			// Resolve on the appliance, never from a remote CLI client's environment.
			return executeOnAppliance(ctx, api, out, "show system ssh")
		}
		policy, err := sshRuntimePolicy(ctx, store)
		if err != nil {
			return err
		}
		cfg, err := store.Load(ctx)
		if err != nil {
			return err
		}
		fields := sshProfileFields(policy, cfg.System.SSH.ShellMode)
		if out != nil {
			values := map[string]string{
				"allow_password":         yesNoStr(policy.AllowPassword),
				"password_source":        policy.PasswordSource,
				"authorized_keys_dir":    policy.AuthorizedKeysDir,
				"host_key_rotation_days": fmt.Sprint(policy.HostKeyRotationDays),
				"shell_mode":             fields.ShellMode,
				"shell_mode_source":      policy.ShellModeSource,
			}
			if fields.ShellModeSaved != nil {
				values["shell_mode_saved"] = displaySavedShell(*fields.ShellModeSaved)
			}
			kvTable(out, values)
		}
		return nil
	}
}

func sshRuntimePolicy(ctx context.Context, store config.Store) (config.SSHRuntimePolicy, error) {
	reader, ok := store.(interface {
		SSHRuntimePolicy(context.Context) (config.SSHRuntimePolicy, error)
	})
	if !ok {
		return config.SSHRuntimePolicy{}, errors.New("SSH runtime policy unavailable")
	}
	return reader.SSHRuntimePolicy(ctx)
}

// showSSHShellMode prints the shell mode SSH runs and its source, and the
// saved mode when it differs: the environment overrides it, or it applies
// at the next start.
func showSSHShellMode(ctx context.Context, store config.Store, out io.Writer, saved string) error {
	policy, err := sshRuntimePolicy(ctx, store)
	if err != nil {
		return monitoringUnavailable(out, "SSH shell mode", err)
	}
	fmt.Fprintf(out, "ssh.shell_mode: %s\n", policy.ShellMode)
	fmt.Fprintf(out, "ssh.shell_mode_source: %s\n", policy.ShellModeSource)
	fields := sshProfileFields(policy, saved)
	if fields.ShellModeSaved == nil {
		return nil
	}
	saved = displaySavedShell(*fields.ShellModeSaved)
	switch {
	case fields.ShellModeSource == "profile":
		fmt.Fprintf(out, "ssh.shell_mode_saved: %s (overridden by profile)\n", saved)
	case policy.ShellModeSource == config.SSHShellModeSourceEnvironment:
		fmt.Fprintf(out, "ssh.shell_mode_saved: %s (overridden by %s)\n", saved, config.EnvSSHShellMode)
	default:
		fmt.Fprintf(out, "ssh.shell_mode_saved: %s (applies after restart)\n", saved)
	}
	return nil
}

func sshProfileFields(policy config.SSHRuntimePolicy, saved string) config.SSHProfileFields {
	fields := config.SSHProfileFields{ShellMode: policy.ShellMode, ShellModeSource: policy.ShellModeSource}
	switch policy.ShellModeSource {
	case config.SSHShellModeSourceProfile:
		fields.ShellModeSource = "profile"
	case config.SSHShellModeSourceEnvironment:
		fields.ShellModeSource = "environment"
	}
	resolved, _ := config.ResolveSSHShellMode(saved, "")
	if resolved != fields.ShellMode {
		fields.ShellModeSaved = &saved
	}
	return fields
}

func displaySavedShell(saved string) string {
	if saved == "" {
		return `""`
	}
	return saved
}

// executeOnAppliance runs line through the appliance's CLI endpoint and
// writes its output, also when the command reports an error.
func executeOnAppliance(ctx context.Context, api *API, out io.Writer, line string) error {
	body, err := json.Marshal(map[string]string{"line": line})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.BaseURL+"/api/v1/cli/execute", bytes.NewReader(body))
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
		return fmt.Errorf("%s: unexpected status %d", line, resp.StatusCode)
	}
	var result struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if out != nil {
		if _, err := io.WriteString(out, result.Output); err != nil {
			return err
		}
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}
