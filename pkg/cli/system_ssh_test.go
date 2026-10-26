// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestSSHPasswordSettingDisplay(t *testing.T) {
	for _, tc := range []struct {
		value *bool
		want  string
	}{
		{nil, "auto (bootstrap/lab)"},
		{new(false), "no"},
		{new(true), "yes"},
	} {
		if got := sshPasswordSetting(tc.value); got != tc.want {
			t.Fatalf("display = %q, want %q", got, tc.want)
		}
	}
}

func TestShowSystemSSHReportsAppliancePolicy(t *testing.T) {
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetSSHRuntimePolicyReader(func(context.Context) (config.SSHRuntimePolicy, error) {
		return config.SSHRuntimePolicy{
			AllowPassword:     true,
			PasswordSource:    "environment (CONTAIND_SSH_ALLOW_PASSWORD)",
			AuthorizedKeysDir: "/appliance/keys",
		}, nil
	})
	ctx := WithRole(context.Background(), string(RoleView))
	serverRegistry := NewRegistry(store, &API{})
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"POST /api/v1/cli/execute": func(req *http.Request) (*http.Response, error) {
			payload := decodeJSONRequest[struct {
				Line string `json:"line"`
			}](t, req)
			if payload.Line != "show system ssh" {
				t.Fatalf("unexpected remote command: %q", payload.Line)
			}
			var output bytes.Buffer
			if err := serverRegistry.ParseAndExecute(ctx, payload.Line, &output); err != nil {
				t.Fatal(err)
			}
			return jsonHTTPResponse(http.StatusOK, map[string]string{"output": output.String()}, nil), nil
		},
	}}
	// The local environment must not substitute for the appliance's resolver.
	t.Setenv("CONTAIND_SSH_ALLOW_PASSWORD", "0")
	var output bytes.Buffer
	remote := NewRegistry(nil, &API{BaseURL: "http://localhost:8080", Client: client})
	if err := remote.ParseAndExecute(ctx, "show system ssh", &output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"allow_password", "yes", "environment (CONTAIND_SSH_ALLOW_PASSWORD)", "/appliance/keys"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %q", want, output.String())
		}
	}
}

func TestShowSystemSSHRemoteFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   any
	}{
		{"http", http.StatusServiceUnavailable, nil},
		{"resolver", http.StatusOK, map[string]string{"error": "SSH runtime policy unavailable"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
				"POST /api/v1/cli/execute": func(*http.Request) (*http.Response, error) {
					return jsonHTTPResponse(tc.status, tc.body, nil), nil
				},
			}}
			api := &API{BaseURL: "http://localhost:8080", Client: client}
			if err := showSystemSSH(nil, api)(context.Background(), nil, nil); err == nil {
				t.Fatal("remote failure was hidden")
			}
		})
	}
}

func TestSSHPasswordCommandPreservesFalse(t *testing.T) {
	posted := false
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/config/candidate": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(http.StatusOK, config.DefaultConfig(), nil), nil
		},
		"POST /api/v1/config/candidate": func(req *http.Request) (*http.Response, error) {
			cfg := decodeJSONRequest[config.Config](t, req)
			if cfg.System.SSH.AllowPassword == nil || *cfg.System.SSH.AllowPassword {
				t.Fatal("explicit false was omitted from the candidate")
			}
			posted = true
			return jsonHTTPResponse(http.StatusOK, nil, nil), nil
		},
	}}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	if err := setSystemSSHAllowPasswordAPI(api)(context.Background(), nil, []string{"false"}); err != nil {
		t.Fatal(err)
	}
	if !posted {
		t.Fatal("no candidate was posted")
	}
}
