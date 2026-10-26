// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import "github.com/tonylturner/containd/pkg/common"

// ListenAddr resolves the engine listener for both planes. Combined mode keeps
// the unauthenticated API on loopback; split mode permits private-network access.
func ListenAddr(combined bool) string {
	if addr := common.EnvTrimmed("CONTAIND_ENGINE_ADDR", ""); addr != "" {
		return addr
	}
	if combined {
		return "127.0.0.1:8081"
	}
	return ":8081"
}
