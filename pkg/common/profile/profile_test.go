// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"os"
	"strings"
	"sync"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  Profile
		err   string
	}{
		{"", Training, ""},
		{"  ", Training, ""},
		{"training", Training, ""},
		{" STRICT ", Strict, ""},
		{"prod", "", `CONTAIND_PROFILE="prod": use training or strict`},
	} {
		t.Run(tt.value, func(t *testing.T) {
			got, err := Parse(tt.value)
			if got != tt.want || errorText(err) != tt.err {
				t.Fatalf("Parse = %q, %v; want %q, %q", got, err, tt.want, tt.err)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	for _, value := range []string{"", "strict", "invalid"} {
		t.Run(value, func(t *testing.T) {
			loaded.once = sync.Once{}
			loaded.value, loaded.err, loaded.defaulted = "", nil, false
			t.Cleanup(func() {
				loaded.once = sync.Once{}
				loaded.value, loaded.err, loaded.defaulted = "", nil, false
			})
			t.Setenv(EnvVar, value)
			if Current() != Training || IsStrict() {
				t.Fatal("Current before Load must be training")
			}
			got, err := Load()
			t.Setenv(EnvVar, "training")
			cached, cachedErr := Load()
			if got != cached || err != cachedErr || Defaulted() != (value == "") {
				t.Fatalf("Load did not cache: %q %v => %q %v", got, err, cached, cachedErr)
			}
			if IsStrict() != (value == "strict") {
				t.Fatal("incorrect strict predicate")
			}
		})
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestStrictPreflight(t *testing.T) {
	const prefix = "CONTAIND_PROFILE=strict refuses "
	for _, tt := range []struct {
		name, key, value, want string
		socket                 bool
	}{
		{"S1", "CONTAIND_LAB_MODE", "TRUE", prefix + "CONTAIND_LAB_MODE=1: lab mode is training-only", false},
		{"S2 empty", "CONTAIND_JWT_SECRET", "", prefix + "CONTAIND_JWT_SECRET: set a unique secret of at least 32 characters (openssl rand -hex 32)", false},
		{"S2 short", "CONTAIND_JWT_SECRET", strings.Repeat("a", 31), prefix + "CONTAIND_JWT_SECRET: set a unique secret of at least 32 characters (openssl rand -hex 32)", false},
		{"S2 example", "CONTAIND_JWT_SECRET", "containd-dev-secret-change-me", prefix + "CONTAIND_JWT_SECRET: set a unique secret of at least 32 characters (openssl rand -hex 32)", false},
		{"S3 admin", "CONTAIND_ADMIN_TOKEN", "private", prefix + "CONTAIND_ADMIN_TOKEN/CONTAIND_AUDITOR_TOKEN: static bearer tokens are training-only", false},
		{"S3 auditor", "CONTAIND_AUDITOR_TOKEN", "private", prefix + "CONTAIND_ADMIN_TOKEN/CONTAIND_AUDITOR_TOKEN: static bearer tokens are training-only", false},
		{"S4", "CONTAIND_DEFAULT_ADMIN_PASSWORD", "private", prefix + "CONTAIND_DEFAULT_ADMIN_PASSWORD: strict issues a one-time first-admin password", false},
		{"S5", "CONTAIND_COOKIE_SECURE", "0", prefix + `CONTAIND_COOKIE_SECURE="0": session cookies are always Secure`, false},
		{"S6", "CONTAIND_SSH_SHELL_MODE", "linux", prefix + `CONTAIND_SSH_SHELL_MODE="linux": the Linux shell is training-only`, false},
		{"S7", "", "", prefix + "a mounted Docker socket (/var/run/docker.sock)", true},
		{"S8", "CONTAIND_MGMT_RESERVATION", "{}", prefix + "CONTAIND_MGMT_RESERVATION: the reserved management path serves plain HTTP", false},
		{"valid", "CONTAIND_COOKIE_SECURE", "TrUe", "", false},
		{"valid appliance", "CONTAIND_SSH_SHELL_MODE", "APPLIANCE", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{"CONTAIND_JWT_SECRET": strings.Repeat("a", 32), tt.key: tt.value}
			// A missing key in this fixture is not an environment variable.
			calls := 0
			err := StrictPreflight("all", func(k string) string { return env[k] }, func(path string) (os.FileInfo, error) {
				calls++
				if path != "/var/run/docker.sock" {
					t.Fatalf("unexpected stat: %s", path)
				}
				if tt.socket {
					return nil, nil
				}
				return nil, os.ErrNotExist
			})
			if errorText(err) != tt.want || calls > 1 {
				t.Fatalf("preflight = %v, stat calls = %d; want %q", err, calls, tt.want)
			}
			if (tt.name == "S7" || tt.name == "valid") && calls != 1 {
				t.Fatal("all mode must check the socket exactly once")
			}
		})
	}
}

func TestStrictPreflightModeSubsetsAndOrdering(t *testing.T) {
	for _, mode := range []string{"all", "mgmt", "engine", "cli", "healthcheck", "version", "enginecredentials"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			err := StrictPreflight(mode, func(string) string { return "" }, func(string) (os.FileInfo, error) {
				calls++
				return nil, nil
			})
			switch mode {
			case "all", "mgmt":
				if err == nil || !strings.Contains(err.Error(), "CONTAIND_JWT_SECRET") || calls != 0 {
					t.Fatalf("management did not check S2 before S7: %v, %d", err, calls)
				}
			case "engine":
				if err == nil || !strings.Contains(err.Error(), "mounted Docker socket") || calls != 1 {
					t.Fatalf("engine subset = %v, %d", err, calls)
				}
			default:
				if err != nil || calls != 0 {
					t.Fatalf("non-server preflight = %v, %d", err, calls)
				}
			}
		})
	}
	err := StrictPreflight("all", func(string) string { return "1" }, func(string) (os.FileInfo, error) {
		t.Fatal("S7 ran before S1")
		return nil, nil
	})
	if errorText(err) != Refusal("CONTAIND_LAB_MODE=1", "lab mode is training-only").Error() {
		t.Fatalf("first refusal = %v", err)
	}
}

func TestStrictPreflightSocketInspectionFailure(t *testing.T) {
	err := StrictPreflight("engine", func(string) string { return "" }, func(string) (os.FileInfo, error) {
		return nil, os.ErrPermission
	})
	if err == nil || !strings.Contains(err.Error(), "to inspect the Docker socket") {
		t.Fatalf("inspection failure was ignored: %v", err)
	}
}
