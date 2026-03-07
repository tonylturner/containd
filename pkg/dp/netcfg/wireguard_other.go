// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package netcfg

import (
	"context"
	"fmt"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func ApplyWireGuard(ctx context.Context, cfg config.WireGuardConfig) error {
	_ = ctx
	_ = cfg
	return fmt.Errorf("wireguard apply not supported on this platform")
}

