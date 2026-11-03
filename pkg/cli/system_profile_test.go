// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/profile"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestSystemProfileView(t *testing.T) {
	for _, strict := range []bool{false, true} {
		saved := config.DefaultConfig()
		saved.System.Mgmt.EnableHTTPS = new(false)
		saved.System.Mgmt.EnableHSTS = new(false)
		effective, fields := systemProfileView(saved, strict)
		if fields.HTTPEnabled == strict || fields.HTTPSEnabled != strict || fields.HSTSEnabled != strict {
			t.Fatalf("strict=%v fields=%+v", strict, fields)
		}
		if strict {
			if fields.HTTPEnabledSource != "profile" || fields.HTTPSEnabledSource != "profile" || fields.HSTSEnabledSource != "profile" ||
				fields.HTTPEnabledSaved == nil || !*fields.HTTPEnabledSaved ||
				fields.HTTPSEnabledSaved == nil || *fields.HTTPSEnabledSaved || fields.HSTSEnabledSaved == nil || *fields.HSTSEnabledSaved {
				t.Fatalf("missing saved/source fields: %+v", fields)
			}
			*effective.System.Mgmt.EnableHTTPS = false
		}
		if *saved.System.Mgmt.EnableHTTPS || *saved.System.Mgmt.EnableHSTS {
			t.Fatal("status mutated saved intent")
		}
	}
	_, fields := systemProfileView(&config.Config{}, false)
	if fields.HTTPEnabledSource != "default" || fields.HTTPSEnabledSource != "default" || fields.HSTSEnabledSource != "default" {
		t.Fatalf("unset sources: %+v", fields)
	}
	agreeing := &config.Config{}
	agreeing.System.Mgmt.EnableHTTPS = new(true)
	_, fields = systemProfileView(agreeing, true)
	if fields.HTTPSEnabledSource != "config" || fields.HTTPSEnabledSaved != nil ||
		fields.HSTSEnabledSource != "default" || fields.HSTSEnabledSaved != nil {
		t.Fatalf("agreeing values incorrectly reported as overridden: %+v", fields)
	}
}

func TestSystemStrictProfile(t *testing.T) {
	if os.Getenv("CONTAIND_TEST_STRICT_CLI") != "1" {
		t.Setenv(profile.EnvVar, "strict")
		t.Setenv("CONTAIND_TEST_STRICT_CLI", "1")
		output, err := exec.Command(os.Args[0], "-test.run=^TestSystemStrictProfile$", "-test.v").CombinedOutput()
		if err != nil {
			t.Fatalf("strict subprocess: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	if _, err := profile.Load(); err != nil || !profile.IsStrict() {
		t.Fatalf("strict profile: %v", err)
	}
	policy := config.SSHRuntimePolicy{ShellMode: "appliance", ShellModeSource: config.SSHShellModeSourceProfile}
	store := shellModeStore(t, policy)
	saved := config.DefaultConfig()
	saved.System.SSH.ShellMode = "linux"
	saved.System.Mgmt.EnableHTTPS = new(false)
	saved.System.Mgmt.EnableHSTS = new(false)
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/config": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(200, saved, nil), nil
		},
		"GET /api/v1/health": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(200, map[string]string{"component": "mgmt"}, nil), nil
		},
	}}
	var out bytes.Buffer
	if err := showSystem(store, &API{BaseURL: "http://test", Client: client})(context.Background(), &out, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Listener settings: effective next-start configuration projected from saved settings (not environment address overrides or live socket state).\n",
		"_source identifies value authority; _saved shows overridden saved configuration.\n",
		"mgmt.http_enabled: no\n", "mgmt.http_enabled_source: profile\n", "mgmt.http_enabled_saved: yes\n",
		"mgmt.https_enabled: yes\n", "mgmt.https_enabled_source: profile\n", "mgmt.https_enabled_saved: no\n",
		"mgmt.hsts: yes\n", "mgmt.hsts_source: profile\n", "mgmt.hsts_saved: no\n",
		"ssh.shell_mode: appliance\n", "ssh.shell_mode_source: profile (strict)\n",
		"ssh.shell_mode_saved: linux (overridden by profile)\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, &out)
		}
	}
}

func TestSystemSSHShellModeSavedFields(t *testing.T) {
	policy := config.SSHRuntimePolicy{ShellMode: "appliance", ShellModeSource: config.SSHShellModeSourceProfile}
	fields := sshProfileFields(policy, "linux")
	if fields.ShellModeSource != "profile" || fields.ShellModeSaved == nil || *fields.ShellModeSaved != "linux" {
		t.Fatalf("strict fields: %+v", fields)
	}
	if got := sshProfileFields(policy, "appliance"); got.ShellModeSource != "profile" || got.ShellModeSaved != nil {
		t.Fatalf("agreeing saved value: %+v", got)
	}
	policy.ShellMode = "linux"
	policy.ShellModeSource = config.SSHShellModeSourceEnvironment
	if got := sshProfileFields(policy, ""); got.ShellModeSaved == nil || *got.ShellModeSaved != "" {
		t.Fatalf("literal empty saved value lost: %+v", got)
	}
	store := shellModeStore(t, config.SSHRuntimePolicy{ShellMode: "appliance", ShellModeSource: config.SSHShellModeSourceProfile})
	saved := config.DefaultConfig()
	saved.System.SSH.ShellMode = "linux"
	if err := store.Save(context.Background(), saved); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if err := showSystemSSH(store, nil)(context.Background(), out, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "profile (strict)") || !strings.Contains(out.String(), "shell_mode_saved") || !strings.Contains(out.String(), "linux") {
		t.Fatalf("missing strict source or saved mode: %s", out)
	}
}

func TestSetSystemSSHShellModeSurfacesStrictValidation(t *testing.T) {
	baseline := config.DefaultConfig()
	posted := false
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/config/candidate": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(200, baseline, nil), nil
		},
		"POST /api/v1/config/candidate": func(req *http.Request) (*http.Response, error) {
			next := decodeJSONRequest[config.Config](t, req)
			posted = true
			err := config.ValidateProfileWrite(baseline, &next, true)
			if err == nil {
				t.Fatal("strict accepted newly introduced linux mode")
			}
			return jsonHTTPResponse(400, map[string]string{"error": err.Error()}, nil), nil
		},
	}}
	var out bytes.Buffer
	err := NewRegistry(nil, &API{BaseURL: "http://test", Client: client}).ParseAndExecute(
		WithRole(context.Background(), string(RoleAdmin)), "set system ssh shell-mode linux", &out)
	if err == nil || !strings.Contains(err.Error(), "the Linux shell is training-only (CONTAIND_PROFILE=strict)") || !posted || out.Len() != 0 {
		t.Fatalf("validation error=%v posted=%v output=%q", err, posted, &out)
	}
}
