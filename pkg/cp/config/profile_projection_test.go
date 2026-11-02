// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestProjectProfile(t *testing.T) {
	f := false
	saved := DefaultConfig()
	saved.System.SSH.ShellMode = SSHShellModeLinux
	saved.System.Mgmt.EnableHTTPS = &f
	saved.System.Mgmt.EnableHSTS = &f
	before, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	effective, overrides := ProjectProfile(saved, true)
	if effective == saved || effective.System.SSH.ShellMode != SSHShellModeAppliance ||
		!*effective.System.Mgmt.EnableHTTPS || !*effective.System.Mgmt.EnableHSTS || *effective.System.Mgmt.EnableHTTP {
		t.Fatalf("incorrect effective config: %+v", effective.System)
	}
	want := []ProfileOverride{
		{"system.ssh.shellMode", "linux", "appliance"},
		{"system.mgmt.enableHTTPS", "false", "true"},
		{"system.mgmt.enableHSTS", "false", "true"},
		{"system.mgmt.enableHTTP", "true", "false"},
	}
	if !reflect.DeepEqual(overrides, want) {
		t.Fatalf("overrides = %+v", overrides)
	}
	*effective.System.Mgmt.EnableHTTPS = false
	after, err := json.Marshal(saved)
	if err != nil || string(after) != string(before) {
		t.Fatalf("projection changed saved config: %v", err)
	}
	training, overrides := ProjectProfile(saved, false)
	if !reflect.DeepEqual(training, saved) || training == saved || len(overrides) != 0 {
		t.Fatal("training projection changed values")
	}
	if got, overrides := ProjectProfile(nil, true); got != nil || overrides != nil {
		t.Fatal("nil projection must remain nil")
	}
}

func TestProjectProfileDefaults(t *testing.T) {
	effective, overrides := ProjectProfile(&Config{}, true)
	if len(overrides) != 1 || overrides[0].Field != "system.mgmt.enableHTTP" ||
		!*effective.System.Mgmt.EnableHTTPS || !*effective.System.Mgmt.EnableHSTS || *effective.System.Mgmt.EnableHTTP {
		t.Fatalf("default semantics: %+v, %+v", effective.System, overrides)
	}
	_, again := ProjectProfile(effective, true)
	if len(again) != 0 {
		t.Fatalf("projection is not idempotent: %+v", again)
	}
}

func TestValidateProfileWrite(t *testing.T) {
	for _, tt := range []struct {
		name, message string
		weaken        func(*Config)
	}{
		{"shell", `ssh.shellMode "linux": the Linux shell is training-only (CONTAIND_PROFILE=strict)`, func(c *Config) { c.System.SSH.ShellMode = "linux" }},
		{"HTTPS", "mgmt.enableHTTPS false: HTTPS is mandatory (CONTAIND_PROFILE=strict)", func(c *Config) { f := false; c.System.Mgmt.EnableHTTPS = &f }},
		{"HSTS", "mgmt.enableHSTS false: HSTS is mandatory (CONTAIND_PROFILE=strict)", func(c *Config) { f := false; c.System.Mgmt.EnableHSTS = &f }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			baseline, next := DefaultConfig(), DefaultConfig()
			tt.weaken(next)
			if err := ValidateProfileWrite(baseline, next, true); err == nil || err.Error() != tt.message {
				t.Fatalf("weakening = %v; want %s", err, tt.message)
			}
			if err := ValidateProfileWrite(baseline, next, false); err != nil {
				t.Fatalf("training refused: %v", err)
			}
			tt.weaken(baseline)
			next.Description = "unrelated edit"
			if err := ValidateProfileWrite(baseline, next, true); err != nil {
				t.Fatalf("carried value refused: %v", err)
			}
			repaired := DefaultConfig()
			if err := ValidateProfileWrite(baseline, repaired, true); err != nil {
				t.Fatalf("repair refused: %v", err)
			}
			if err := ValidateProfileWrite(repaired, next, true); err == nil {
				t.Fatal("reintroducing weakness after repair was allowed")
			}
		})
	}
	if err := ValidateProfileWrite(nil, DefaultConfig(), true); err != nil {
		t.Fatalf("factory defaults refused: %v", err)
	}
	if err := ValidateProfileWrite(nil, nil, true); err != nil {
		t.Fatal(err)
	}
}

func TestProjectProfileResponseSchema(t *testing.T) {
	f, shell := false, ""
	status := ProfileStatusFields{
		TLS: TLSProfileFields{HTTPEnabledSource: "profile", HTTPEnabledSaved: &f},
		SSH: SSHProfileFields{ShellMode: "appliance", ShellModeSource: "profile", ShellModeSaved: &shell},
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"httpEnabled":false`, `"httpEnabledSaved":false`, `"httpEnabledSource":"profile"`, `"shellModeSaved":""`, `"shellModeSource":"profile"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %s in %s", want, data)
		}
	}
	if strings.Contains(string(data), "httpRedirectsSource") {
		t.Fatal("redirect-only schema survived HTTPS-only cutover")
	}
}
