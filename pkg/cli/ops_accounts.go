// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func opsCreateUser(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		const usage = "usage: create user <username> [--role admin|view] [--first-name <name>] [--last-name <name>] [--email <email>] (immediate; password prompted twice)"
		if len(args) == 0 || strings.TrimSpace(args[0]) == "" || strings.HasPrefix(args[0], "--") || len(args)%2 != 1 {
			return fmt.Errorf("%s", usage)
		}
		payload := map[string]string{"username": args[0], "role": "view"}
		fields := map[string]string{"--role": "role", "--first-name": "firstName", "--last-name": "lastName", "--email": "email"}
		seen := map[string]bool{}
		for i := 1; i < len(args); i += 2 {
			field, ok := fields[args[i]]
			if !ok || seen[field] {
				return fmt.Errorf("%s", usage)
			}
			seen[field] = true
			payload[field] = args[i+1]
		}
		if payload["role"] != "admin" && payload["role"] != "view" {
			return fmt.Errorf("%s", usage)
		}
		password, err := confirmedPassword(ctx)
		if err != nil {
			return err
		}
		payload["password"] = password
		return accountSecretMutation(ctx, api, out, "/api/v1/users", payload, "User created.")
	}
}

func opsResetUserPassword(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
			return fmt.Errorf("usage: reset user password <username|id> (immediate; password prompted twice)")
		}
		password, err := confirmedPassword(ctx)
		if err != nil {
			return err
		}
		var accounts *[]struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		}
		if err := api.getJSON(ctx, "/api/v1/users", &accounts); err != nil {
			return err
		}
		if accounts == nil {
			return fmt.Errorf("user list unavailable; no password reset requested")
		}
		id := ""
		for _, account := range *accounts {
			if account.ID == args[0] || account.Username == args[0] {
				if account.ID == "" || id != "" && id != account.ID {
					return fmt.Errorf("ambiguous user target; no password reset requested")
				}
				id = account.ID
			}
		}
		if id == "" {
			return fmt.Errorf("user not found; no password reset requested")
		}
		return accountSecretMutation(ctx, api, out, "/api/v1/users/"+url.PathEscape(id)+"/password",
			map[string]string{"password": password}, "Password reset.")
	}
}

// Never print a secret-bearing response, including an error body: an upstream
// server or proxy might reflect the request in an arbitrary encoding.
func accountSecretMutation(ctx context.Context, api *API, out io.Writer, path string, payload map[string]string, success string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, _, err = api.requestBytes(ctx, http.MethodPost, path, body, "")
	if err != nil {
		return fmt.Errorf("account operation failed; check account permissions, availability and password policy in System → Users")
	}
	if out != nil {
		fmt.Fprintln(out, success+" Applied immediately; not staged and does not require commit.")
	}
	return nil
}

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
