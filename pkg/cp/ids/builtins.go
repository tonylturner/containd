// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import "github.com/tonylturner/containd/pkg/cp/config"

// BuiltinRules returns the default IDS rules that ship with containd.
// Delegates to config.DefaultIDSConfig() to avoid duplication.
func BuiltinRules() []config.IDSRule {
	return config.DefaultIDSConfig().Rules
}
