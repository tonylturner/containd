// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"strings"

	"github.com/tonylturner/containd/pkg/common"
)

// ApplyBootstrapEnvDefaults aligns a freshly seeded config with runtime env
// defaults used by the appliance compose files.
func ApplyBootstrapEnvDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	ifaces := common.EnvCSV("CONTAIND_CAPTURE_IFACES")
	if len(ifaces) > 0 {
		cfg.DataPlane.CaptureInterfaces = ifaces
	}
	cfg.DataPlane.Enforcement = common.EnvBool("CONTAIND_ENFORCE_ENABLED", cfg.DataPlane.Enforcement)
	if cfg.DataPlane.Enforcement && strings.TrimSpace(cfg.DataPlane.EnforceTable) == "" {
		cfg.DataPlane.EnforceTable = "containd"
	}
}
