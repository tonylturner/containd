// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package common

import "strings"

// FirstNonEmpty returns the first non-empty (after trimming) string from the arguments.
func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
