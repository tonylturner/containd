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

func shellModeStore(t *testing.T, policy config.SSHRuntimePolicy) config.Store {
	t.Helper()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.SetSSHRuntimePolicyReader(func(context.Context) (config.SSHRuntimePolicy, error) {
		return policy, nil
	})
	return store
}

// show system reports the shell mode SSH runs, its source, and the saved
// mode when the environment overrides it or a restart has not applied it.
func TestShowSystemShellMode(t *testing.T) {
	env := "environment (CONTAIND_SSH_SHELL_MODE)"
	for _, tc := range []struct {
		saved, mode, source string
		want                []string
		absent              string
	}{
		{"", "appliance", "default", []string{"ssh.shell_mode: appliance\n", "ssh.shell_mode_source: default\n"}, "shell_mode_saved"},
		{"linux", "linux", "config", []string{"ssh.shell_mode: linux\n", "ssh.shell_mode_source: config\n"}, "shell_mode_saved"},
		{"appliance", "linux", env, []string{"ssh.shell_mode: linux\n", "ssh.shell_mode_source: " + env + "\n", "ssh.shell_mode_saved: appliance (overridden by CONTAIND_SSH_SHELL_MODE)\n"}, ""},
		{"linux", "linux", env, []string{"ssh.shell_mode: linux\n"}, "shell_mode_saved"},
		{"linux", "appliance", "default", []string{"ssh.shell_mode: appliance\n", "ssh.shell_mode_saved: linux (applies after restart)\n"}, ""},
	} {
		store := shellModeStore(t, config.SSHRuntimePolicy{ShellMode: tc.mode, ShellModeSource: tc.source})
		var out bytes.Buffer
		if err := showSSHShellMode(context.Background(), store, &out, tc.saved); err != nil {
			t.Fatal(err)
		}
		for _, want := range tc.want {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("%+v: missing %q in %q", tc, want, out.String())
			}
		}
		if tc.absent != "" && strings.Contains(out.String(), tc.absent) {
			t.Fatalf("%+v: unexpected %q in %q", tc, tc.absent, out.String())
		}
	}
	var out bytes.Buffer
	if err := showSSHShellMode(context.Background(), nil, &out, ""); err == nil || !strings.Contains(out.String(), "SSH shell mode unavailable") {
		t.Fatalf("no reader: %v, %q", err, out.String())
	}
}

// A client without the appliance store runs show system on the appliance and
// prints its output, also when the appliance reports an error.
func TestShowSystemRunsOnAppliance(t *testing.T) {
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"POST /api/v1/cli/execute": func(req *http.Request) (*http.Response, error) {
			payload := decodeJSONRequest[struct {
				Line string `json:"line"`
			}](t, req)
			if payload.Line != "show system" {
				t.Fatalf("unexpected remote command: %q", payload.Line)
			}
			return jsonHTTPResponse(http.StatusOK, map[string]string{"output": "ssh.shell_mode: linux\n", "error": "System health unavailable"}, nil), nil
		},
	}}
	t.Setenv("CONTAIND_SSH_SHELL_MODE", "appliance")
	var out bytes.Buffer
	remote := NewRegistry(nil, &API{BaseURL: "http://localhost:8080", Client: client})
	err := remote.ParseAndExecute(WithRole(context.Background(), string(RoleView)), "show system", &out)
	if err == nil || !strings.Contains(out.String(), "ssh.shell_mode: linux") {
		t.Fatalf("output %q, error %v", out.String(), err)
	}
}

// applianceShowSystem is show system as the appliance runs it, with its store.
func applianceShowSystem(t *testing.T) func(*API) Command {
	store := shellModeStore(t, config.SSHRuntimePolicy{ShellMode: "appliance", ShellModeSource: "default"})
	return func(api *API) Command { return showSystem(store, api) }
}
