// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"errors"
	"os"
	"strings"
)

// ErrPasswordChangeLabMode refuses a password change while lab mode pins the
// documented default credential.
var ErrPasswordChangeLabMode = errors.New("password change disabled in lab mode (CONTAIND_LAB_MODE=1) — credentials are pinned to the documented canonical default for reproducible workshop runs")

// LabMode reports whether CONTAIND_LAB_MODE enables lab mode ("1" or "true").
func LabMode() bool {
	v := os.Getenv("CONTAIND_LAB_MODE")
	return v == "1" || strings.EqualFold(v, "true")
}

// CheckPasswordChange returns ErrPasswordChangeLabMode when lab mode pins
// credentials, and nil otherwise. Every password change for any user is
// subject to this rule; SetPassword enforces it, and callers that prompt for a
// new password consult it first so they refuse before collecting one.
// Seeding the default admin is not a change and is not affected.
func CheckPasswordChange() error {
	if LabMode() {
		return ErrPasswordChangeLabMode
	}
	return nil
}
