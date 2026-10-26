// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package labmode reports whether the process runs in lab mode.
//
// Lab mode is a process-wide setting selected by the CONTAIND_LAB_MODE
// environment variable. It relaxes management authentication, pins the
// documented default credential and enables SSH password login by default, so
// it is meant only for isolated training and development environments.
package labmode

import (
	"os"
	"strings"
)

// envVar names the environment variable that enables lab mode.
const envVar = "CONTAIND_LAB_MODE"

// Enabled reports whether CONTAIND_LAB_MODE enables lab mode. Only "1" and a
// case-insensitive "true" enable it; any other value, including an unset
// variable, leaves lab mode off.
func Enabled() bool {
	v := os.Getenv(envVar)
	return v == "1" || strings.EqualFold(v, "true")
}
