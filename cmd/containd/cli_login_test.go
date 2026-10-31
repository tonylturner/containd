// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCLILoginAssurance(t *testing.T) {
	t.Setenv("CONTAIND_CLI_USER", "operator")
	t.Setenv("CONTAIND_CLI_PASSWORD", "private-input")
	for _, tt := range []struct{ name, body, want string }{
		{"MFA", `{"mfaRequired":true,"mfaChallengeToken":"private-challenge"}`, "requires MFA"},
		{"password", `{"token":"private-token","user":{"mustChangePassword":true}}`, "requires a password change"},
		{"both", `{"mfaRequired":true,"user":{"mustChangePassword":true}}`, "requires a password change"},
		{"enrollment", `{"token":"private-token","user":{"mfaRequired":true}}`, "requires MFA enrollment"},
		{"normal", `{"token":"session-token"}`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				if r.URL.Path != "/api/v1/auth/login" || r.Method != http.MethodPost || body["username"] != "operator" || body["password"] != "private-input" {
					t.Error("unexpected login request")
				}
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			token, err := cliLogin(context.Background(), srv.URL, srv.Client())
			if tt.want == "" {
				if err != nil || token != "session-token" {
					t.Fatalf("login = %q, %v", token, err)
				}
				return
			}
			if token != "" || err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("login = %q, %v; want %s", token, err, tt.want)
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatal("error leaks credentials")
			}
		})
	}
}
