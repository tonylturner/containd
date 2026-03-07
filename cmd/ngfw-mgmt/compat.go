// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package main

import (
	mgmtapp "github.com/tonylturner/containd/pkg/app/mgmt"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// Wrappers preserved for existing tests.
func mgmtAllowedOnInterface(cfg *config.Config, ifaceName string, isTLS bool) bool {
	return mgmtapp.MgmtAllowedOnInterface(cfg, ifaceName, isTLS)
}

func sshAllowedOnInterface(cfg *config.Config, ifaceName string) bool {
	return mgmtapp.SSHAllowedOnInterface(cfg, ifaceName)
}
