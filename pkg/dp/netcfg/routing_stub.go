// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package netcfg

import (
	"context"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func applyRouting(ctx context.Context, routing config.RoutingConfig, opts ApplyRoutingOptions) error {
	_ = ctx
	_ = routing
	_ = opts
	// No-op on non-Linux platforms.
	return nil
}

