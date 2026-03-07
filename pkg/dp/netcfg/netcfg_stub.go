// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package netcfg

import (
	"context"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func applyInterfaces(ctx context.Context, ifaces []config.Interface, opts ApplyOptions) error {
	_ = ctx
	_ = ifaces
	_ = opts
	// No-op on non-Linux platforms.
	return nil
}
