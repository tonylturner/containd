// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cli"
)

type secretHTTPClient func(*http.Request) (*http.Response, error)

func (f secretHTTPClient) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestSSHCLISecretInput(t *testing.T) {
	const password = "  Secret1 with spaces  "
	for _, tc := range []struct {
		name, input, want string
		pty               bool
		status, posts     int
	}{
		{"success", password + "\n" + password + "\n", "User created", true, 200, 1},
		{"mismatch", password + "\nSecret2\n", "passwords do not match", true, 200, 0},
		{"cancel", "partial\x03", "cancelled", true, 200, 0},
		{"blank", "\n", "cancelled", true, 200, 0},
		{"eof", "partial", "cancelled", true, 200, 0},
		{"no PTY", "", "piped sessions do not take secret input", false, 200, 0},
		{"API refusal", password + "\n" + password + "\n", "account operation failed", true, 400, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, audits := newTestSSHServer(t)
			posts := 0
			client := secretHTTPClient(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/api/v1/users":
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					posts++
					if r.Method != http.MethodPost || body["password"] != password {
						t.Fatal("password changed or unexpected mutation")
					}
					return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(password))}, nil
				case "/api/v1/auth/me":
					return jsonResponse(200, map[string]string{"username": "containd", "role": "admin"}), nil
				default:
					// Status is independent of the account operation.
					return jsonResponse(200, map[string]any{}), nil
				}
			})
			srv.opts.APIClient = client
			api := &cli.API{BaseURL: "http://appliance", Client: client}
			reg := cli.NewRegistry(nil, api)
			// After a cancelled/failed entry, the next command still executes.
			commands := "create user bob\n" + tc.input
			if tc.name != "eof" {
				commands += "show version\nexit\n"
			}
			input := newSessionInput(strings.NewReader(commands))
			defer input.close()
			var output bytes.Buffer
			var pr *ptyRequest
			if tc.pty {
				pr = &ptyRequest{}
			}
			srv.repl(cli.WithRole(context.Background(), "admin"), "containd", "test", reg, &sessionIO{sessionInput: input, Writer: &output}, pr, nil)
			if posts != tc.posts || !strings.Contains(output.String(), tc.want) ||
				strings.Contains(output.String(), password) || strings.Contains(output.String(), "Secret2") {
				t.Fatalf("unexpected request count or terminal output: posts=%d", posts)
			}
			if tc.name != "eof" && (len(audits.records) != 2 || audits.records[1].Target != "show version") {
				t.Fatal("subsequent show version did not run")
			}
			if len(audits.records) == 0 || audits.records[0].Target != "create user bob" {
				t.Fatal("missing command audit")
			}
			if strings.Contains(fmt.Sprint(audits.records), password) || strings.Contains(fmt.Sprint(audits.records), "Secret2") {
				t.Fatal("secret included in audit")
			}
		})
	}
}
