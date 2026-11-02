// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// StrictPreflight checks strict startup invariants in refusal order. The caller
// selects it only for Strict. Engine mode checks only the Docker socket; all and
// mgmt check the full set. Non-server modes have no startup checks.
func StrictPreflight(mode string, env func(string) string, stat func(string) (os.FileInfo, error)) error {
	mgmt := mode == "all" || mode == "mgmt"
	if !mgmt && mode != "engine" {
		return nil
	}
	if mgmt {
		// Match labmode.Enabled, including its treatment of whitespace.
		if v := env("CONTAIND_LAB_MODE"); v == "1" || strings.EqualFold(v, "true") {
			return Refusal("CONTAIND_LAB_MODE=1", "lab mode is training-only")
		}
		secret := strings.TrimSpace(env("CONTAIND_JWT_SECRET"))
		if secret == "containd-dev-secret-change-me" || utf8.RuneCountInString(secret) < 32 {
			return Refusal("CONTAIND_JWT_SECRET", "set a unique secret of at least 32 characters (openssl rand -hex 32)")
		}
		if env("CONTAIND_ADMIN_TOKEN") != "" || env("CONTAIND_AUDITOR_TOKEN") != "" {
			return Refusal("CONTAIND_ADMIN_TOKEN/CONTAIND_AUDITOR_TOKEN", "static bearer tokens are training-only")
		}
		if env("CONTAIND_DEFAULT_ADMIN_PASSWORD") != "" {
			return Refusal("CONTAIND_DEFAULT_ADMIN_PASSWORD", "strict issues a one-time first-admin password")
		}
		if v := strings.TrimSpace(env("CONTAIND_COOKIE_SECURE")); v != "" && v != "1" && !strings.EqualFold(v, "true") {
			return Refusal(fmt.Sprintf("CONTAIND_COOKIE_SECURE=%q", v), "session cookies are always Secure")
		}
		if v := strings.TrimSpace(env("CONTAIND_SSH_SHELL_MODE")); v != "" && !strings.EqualFold(v, "appliance") {
			return Refusal(fmt.Sprintf("CONTAIND_SSH_SHELL_MODE=%q", v), "the Linux shell is training-only")
		}
	}
	const socket = "/var/run/docker.sock"
	if _, err := stat(socket); err == nil {
		return Refusal("a mounted Docker socket ("+socket+")", "")
	} else if !errors.Is(err, os.ErrNotExist) {
		// An unobservable socket is not evidence that it is absent.
		return Refusal("to inspect the Docker socket ("+socket+")", err.Error())
	}
	if mgmt && env("CONTAIND_MGMT_RESERVATION") != "" {
		return Refusal("CONTAIND_MGMT_RESERVATION", "the reserved management path serves plain HTTP")
	}
	return nil
}
