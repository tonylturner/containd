// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package netcfg

import (
	"context"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type ApplyOptions struct {
	// Replace, when true, removes any non-desired interface addresses for interfaces
	// that declare Addresses in config (explicit, admin-triggered).
	Replace bool
}

// ApplyInterfaces applies interface addressing intent to the OS.
// Platform-specific implementations may be a no-op on unsupported systems.
func ApplyInterfaces(ctx context.Context, ifaces []config.Interface) error {
	return applyInterfaces(ctx, ifaces, ApplyOptions{})
}

// ApplyInterfacesReplace performs a reconcile pass (replace semantics) for interfaces with configured addresses.
func ApplyInterfacesReplace(ctx context.Context, ifaces []config.Interface) error {
	return applyInterfaces(ctx, ifaces, ApplyOptions{Replace: true})
}

// ApplyRouting converges static routes and policy rules marked with protocol 98.
// Entries with other protocols are never removed or replaced.
func ApplyRouting(ctx context.Context, routing config.RoutingConfig) error {
	return applyRouting(ctx, routing)
}

// ApplyRoutingReplace is the explicit reconcile entry point; ordinary applies
// have the same ownership-scoped convergence semantics.
func ApplyRoutingReplace(ctx context.Context, routing config.RoutingConfig) error {
	return applyRouting(ctx, routing)
}
