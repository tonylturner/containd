// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package common

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	warnedVars sync.Map
)

// Env reads an environment variable, preferring the CONTAIND_ prefix and
// falling back to the legacy NGFW_ prefix with a one-time deprecation warning.
// If neither is set, it returns fallback.
func Env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	// Try legacy NGFW_ prefix if the canonical name starts with CONTAIND_.
	if strings.HasPrefix(name, "CONTAIND_") {
		legacy := "NGFW_" + strings.TrimPrefix(name, "CONTAIND_")
		if v := os.Getenv(legacy); v != "" {
			if _, warned := warnedVars.LoadOrStore(legacy, true); !warned {
				slog.Warn("deprecated env var", "var", legacy, "use", name)
			}
			return v
		}
	}
	return fallback
}

// EnvTrimmed is like Env but trims whitespace from the result.
func EnvTrimmed(name, fallback string) string {
	return strings.TrimSpace(Env(name, fallback))
}

// EnvBool reads an environment variable as a boolean. Truthy values are
// 1,true,yes,on; falsy values are 0,false,no,off. Invalid or unset values
// fall back to fallback.
func EnvBool(name string, fallback bool) bool {
	v := strings.ToLower(EnvTrimmed(name, ""))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

// EnvCSV reads a comma-separated environment variable into trimmed, non-empty
// entries. Unset values return nil.
func EnvCSV(name string) []string {
	raw := EnvTrimmed(name, "")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
