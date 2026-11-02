// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestProfileMainHelper(t *testing.T) {
	if os.Getenv("CONTAIND_TEST_PROFILE_MAIN") != "1" {
		return
	}
	os.Args = []string{"containd", os.Getenv("CONTAIND_TEST_PROFILE_MODE")}
	main()
}

func TestProfileMain(t *testing.T) {
	for _, tt := range []struct {
		name, profile, mode, want string
		code                      int
	}{
		{"training version", "", "version", "containd ", 0},
		{"strict version skips preflight", "strict", "version", "containd ", 0},
		{"invalid profile even for version", "prod", "version", `CONTAIND_PROFILE=\"prod\": use training or strict`, 1},
		{"strict all refuses before planes", "strict", "all", "lab mode is training-only", 1},
		{"strict mgmt refuses before startup", "strict", "mgmt", "lab mode is training-only", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestProfileMainHelper$")
			cmd.Env = append(os.Environ(), "CONTAIND_TEST_PROFILE_MAIN=1", "CONTAIND_TEST_PROFILE_MODE="+tt.mode,
				"CONTAIND_PROFILE="+tt.profile, "CONTAIND_LAB_MODE=1", "CONTAIND_LOG_SYSLOG_ADDR=")
			out, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					code = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tt.code || !strings.Contains(string(out), tt.want) {
				t.Fatalf("exit %d, output %s; want exit %d containing %s", code, out, tt.code, tt.want)
			}
		})
	}
}

func TestProfileCLILoginStatus(t *testing.T) {
	const hint = "authentication failed: login returned 401 (strict profile: the first admin password is the one-time password printed to the container log; set CONTAIND_CLI_USER/CONTAIND_CLI_PASSWORD)"
	if got := fmt.Errorf("authentication failed: %w", cliLoginStatusError(401, true)).Error(); got != hint {
		t.Fatalf("hint = %s", got)
	}
	for _, strict := range []bool{false, true} {
		if got := cliLoginStatusError(403, strict).Error(); got != "login returned 403" {
			t.Fatalf("non-401 changed: %s", got)
		}
	}
	if got := cliLoginStatusError(401, false).Error(); got != "login returned 401" {
		t.Fatalf("training changed: %s", got)
	}
}
