// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func opsUser(api *API, action string) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 2 || args[1] != "CONFIRM" {
			return fmt.Errorf("usage: %s user <id> CONFIRM (immediate)", action)
		}
		path := "/api/v1/users/" + url.PathEscape(args[0])
		method := http.MethodDelete
		var payload any
		if action == "require mfa" {
			method = http.MethodPost
			path += "/mfa/require"
			payload = map[string]any{}
		}
		return opsImmediate(ctx, api, out, method, path, payload)
	}
}

func opsOpenVPN(api *API, action string) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 2 || args[1] != "CONFIRM" {
			return fmt.Errorf("usage: %s openvpn client <name-or-id> CONFIRM (immediate)", action)
		}
		path := "/api/v1/services/vpn/openvpn/clients"
		payload := map[string]any{}
		if action == "issue" {
			payload["name"] = args[0]
		} else {
			path += "/" + url.PathEscape(args[0]) + "/revoke"
		}
		return opsImmediate(ctx, api, out, http.MethodPost, path, payload)
	}
}

func opsBackup(api *API, action string) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		path := "/api/v1/config/backups"
		method := http.MethodPost
		var payload any
		if action == "create" {
			if len(args) != 3 || (args[1] != "redacted" && args[1] != "full") || args[2] != "CONFIRM" {
				return fmt.Errorf("usage: create backup <name> <redacted|full> CONFIRM (immediate; full contains secrets)")
			}
			payload = map[string]any{"name": args[0], "redacted": args[1] == "redacted"}
		} else {
			if len(args) != 2 || args[1] != "CONFIRM" {
				return fmt.Errorf("usage: delete backup <id> CONFIRM (immediate)")
			}
			path += "/" + url.PathEscape(args[0])
			method = http.MethodDelete
		}
		return opsImmediate(ctx, api, out, method, path, payload)
	}
}
