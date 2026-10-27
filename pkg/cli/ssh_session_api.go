// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
)

const (
	// EnvSSHAPISocket names the Unix socket through which CLI processes in a
	// Linux shell opened over SSH call management as that SSH login. The SSH
	// server sets it in the shell and removes the socket when the shell exits.
	EnvSSHAPISocket = "CONTAIND_SSH_API_SOCKET"

	// SSHResetResponseHeader and SSHResetAcknowledgePath coordinate delivery
	// of a factory-reset response to the CLI before its SSH shell is closed.
	SSHResetResponseHeader  = "X-Containd-SSH-Reset"
	SSHResetAcknowledgePath = "/_containd/ssh-reset-complete"
)

// sshSessionBaseURL addresses requests sent over the SSH login's socket.
const sshSessionBaseURL = "http://ssh-session"

// ConnectSSHSession returns an API that calls management through the SSH
// login's socket and checks that the login is still usable. The API holds
// no credentials: the SSH server authenticates each request.
func ConnectSSHSession(ctx context.Context, socket string) (*API, error) {
	var dialer net.Dialer
	api := &API{
		BaseURL: sshSessionBaseURL,
		Client: &http.Client{
			Timeout: defaultHTTPClient.Timeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api.BaseURL+"/api/v1/auth/me", nil)
	if err != nil {
		return nil, err
	}
	resp, err := api.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body) == nil && body.Error != "" {
			return nil, errors.New(body.Error)
		}
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return api, nil
}
