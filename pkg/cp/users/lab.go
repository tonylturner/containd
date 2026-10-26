// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"errors"

	"github.com/tonylturner/containd/pkg/common/labmode"
)

// ErrPasswordChangeLabMode refuses a password change while lab mode pins the
// documented default credential.
var ErrPasswordChangeLabMode = errors.New("password change disabled in lab mode (CONTAIND_LAB_MODE=1) — credentials are pinned to the documented canonical default for reproducible workshop runs")

// CheckPasswordChange returns ErrPasswordChangeLabMode when lab mode pins
// credentials, and nil otherwise. Every password change for any user is
// subject to this rule; SetPassword enforces it, and callers that prompt for a
// new password consult it first so they refuse before collecting one.
// Seeding the default admin is not a change and is not affected.
func CheckPasswordChange() error {
	if labmode.Enabled() {
		return ErrPasswordChangeLabMode
	}
	return nil
}
