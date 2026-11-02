// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/peterh/liner"
	"github.com/tonylturner/containd/pkg/cli"
)

type secretTestClient func(*http.Request) (*http.Response, error)

func (f secretTestClient) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestLocalSecretInputAndHistory(t *testing.T) {
	for _, tc := range []struct {
		name        string
		interactive bool
		promptError error
		wantPosts   int
	}{
		{"terminal", true, nil, 1},
		{"piped", false, nil, 0},
		{"interrupt", true, liner.ErrPromptAborted, 0},
		{"eof", true, io.EOF, 0},
		{"redirected output", true, liner.ErrNotTerminalOutput, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const password = "  Secret1 \t"
			prompts, posts := 0, 0
			api := &cli.API{BaseURL: "http://appliance", Client: secretTestClient(func(r *http.Request) (*http.Response, error) {
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				posts++
				if body["password"] != password {
					t.Fatal("local password changed")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}
			ctx := cliSecretContext(cli.WithRole(context.Background(), "admin"), tc.interactive, func(string) (string, error) {
				prompts++
				return password, tc.promptError
			})
			reg := cli.NewRegistry(nil, api)
			lines := []string{"create user bob", "show version", "exit"}
			var history []string
			var stdout, stderr bytes.Buffer
			err := runCLILoop("", func(string) (string, error) {
				line := lines[0]
				lines = lines[1:]
				return line, nil
			}, func(line string) { history = append(history, line) }, func(line string, out *strings.Builder) error {
				return reg.ParseAndExecute(ctx, line, out)
			}, tc.interactive, &stdout, &stderr)
			if tc.interactive && err != nil || !tc.interactive && !errors.Is(err, errCLISessionCommandFailed) {
				t.Fatalf("session result: %v", err)
			}
			wantPrompts := 2
			if !tc.interactive {
				wantPrompts = 0
			} else if tc.promptError != nil {
				wantPrompts = 1
			}
			if posts != tc.wantPosts || prompts != wantPrompts || len(history) != 3 || history[0] != "create user bob" ||
				strings.Contains(strings.Join(history, "\n")+stdout.String()+stderr.String(), password) ||
				!strings.Contains(stdout.String(), "containd") {
				t.Fatal("secret leaked, unexpected request, or session did not continue")
			}
			if (!tc.interactive || errors.Is(tc.promptError, liner.ErrNotTerminalOutput)) && !strings.Contains(stderr.String(), "piped sessions do not take secret input") {
				t.Fatal("missing piped-input refusal")
			}
		})
	}
}
